<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Blocklist\Parser\ListFormatException;
use OCA\IntrusionDetection\Blocklist\Parser\ParsedList;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Db\BlocklistRangeMapper;
use OCA\IntrusionDetection\Db\BlocklistStatMapper;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Http\Client\IClientService;
use OCP\Http\Client\IResponse;
use OCP\Lock\ILockingProvider;
use OCP\Lock\LockedException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;
use Psr\Log\LoggerInterface;

/**
 * Downloads the enabled lists and switches each to a new version.
 *
 * For each list:
 * 1. Refuse addresses that are not `https://` or point into the local network.
 * 2. Download with `If-Modified-Since` / `If-None-Match`, timeouts, at most
 *    three https redirects (each checked like the address itself), into a
 *    sink that aborts the transfer after MAX_BYTES ({@see LimitedSink}).
 * 3. Parse, and refuse a list that is empty, has more than MAX_ENTRIES
 *    entries, or more than 1 % malformed entries.
 * 4. Write the ranges, merged so they never overlap, as a new version.
 * 5. Switch the list's active version in app config (one write), bump the
 *    address cache so every cached verdict is re-resolved, and delete
 *    versions older than the previous one. The previous version is deleted a
 *    few minutes later, so a request that read the old state just before the
 *    switch still finds its rows.
 *
 * A failure keeps the version in use and is recorded for the admin page and
 * the setup check. All syncs take one lock, so two processes never write the
 * same list or the state at the same time.
 */
class BlocklistSync {
	/** Seconds between downloads of a list that sets no interval of its own */
	public const INTERVAL = 21600;
	public const MAX_BYTES = 10 * 1024 * 1024;
	/** A list with more entries is refused, so a broken or hostile list cannot fill the database */
	public const MAX_ENTRIES = 200000;
	public const MAX_MALFORMED_SHARE = 0.01;
	/** Seconds the previous version is kept after a switch */
	public const PREVIOUS_GRACE = 300;
	/** Matches are kept this many days */
	public const STATS_DAYS = 30;
	private const TIMEOUT = 60;
	private const CONNECT_TIMEOUT = 10;
	private const MAX_REDIRECTS = 3;
	private const LOCK = 'intrusion_detection/blocklist_sync';

	public function __construct(
		private readonly SourceRepository $sources,
		private readonly StateStore $states,
		private readonly BlocklistRangeMapper $ranges,
		private readonly BlocklistStatMapper $stats,
		private readonly IClientService $clientService,
		private readonly UrlPolicy $urlPolicy,
		private readonly CheckSettings $settings,
		private readonly AddressCache $addressCache,
		private readonly ILockingProvider $locking,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * Sync the enabled lists whose interval has passed. Used by the background job.
	 *
	 * @return list<SyncResult>
	 */
	public function syncDue(): array {
		$now = $this->timeFactory->getTime();
		$due = [];
		foreach ($this->activeSources() as $source) {
			$attempt = $this->states->get($source->id)->attemptAt;
			// A minute of slack, so a job that runs a little early does not skip a whole interval.
			if ($attempt === null || $now - $attempt >= $source->effectiveInterval() - 60) {
				$due[] = $source;
			}
		}
		return $this->run($due, false);
	}

	/**
	 * Sync one list, or every enabled list, now. Used by occ.
	 *
	 * @param bool $force download in full, without the conditional request headers
	 * @return list<SyncResult>
	 * @throws \InvalidArgumentException for an unknown list
	 */
	public function sync(?string $id = null, bool $force = false): array {
		if ($id === null) {
			return $this->run($this->activeSources(), $force);
		}
		$source = $this->sources->get($id) ?? throw new \InvalidArgumentException('Unknown list ' . $id);
		return $this->run([$source], $force);
	}

	/**
	 * Whether the background job has anything to download.
	 */
	public function hasActiveSources(): bool {
		return $this->activeSources() !== [];
	}

	/**
	 * The enabled lists that are in use: attribute lists always, blocklists
	 * only while the blocklist check is not off.
	 *
	 * @return list<BlocklistSource>
	 */
	public function activeSources(): array {
		$denyRuns = $this->settings->modeState(BlocklistMatch::ID)->runs();
		return array_values(array_filter($this->sources->enabled(), static fn (BlocklistSource $s): bool => $denyRuns || !$s->isDeny()));
	}

	/**
	 * Remove what is no longer needed: rows of lists that were switched off or
	 * removed, previous versions after their grace period, old match counters.
	 */
	public function cleanup(): void {
		try {
			$this->locking->acquireLock(self::LOCK, ILockingProvider::LOCK_EXCLUSIVE);
		} catch (LockedException) {
			return;
		}
		try {
			$this->cleanupLocked($this->timeFactory->getTime());
		} finally {
			$this->locking->releaseLock(self::LOCK, ILockingProvider::LOCK_EXCLUSIVE);
		}
	}

	/**
	 * @param list<BlocklistSource> $sources
	 * @return list<SyncResult>
	 */
	private function run(array $sources, bool $force): array {
		try {
			$this->locking->acquireLock(self::LOCK, ILockingProvider::LOCK_EXCLUSIVE);
		} catch (LockedException) {
			return array_map(static fn (BlocklistSource $s): SyncResult => new SyncResult($s->id, SyncResult::SKIPPED), $sources);
		}
		try {
			$results = [];
			$switched = false;
			foreach ($sources as $source) {
				$result = $this->syncOne($source, $force);
				$switched = $switched || $result->outcome === SyncResult::UPDATED;
				$results[] = $result;
			}
			if ($switched) {
				$this->addressCache->bump();
			}
			$this->cleanupLocked($this->timeFactory->getTime());
			return $results;
		} finally {
			$this->locking->releaseLock(self::LOCK, ILockingProvider::LOCK_EXCLUSIVE);
		}
	}

	private function syncOne(BlocklistSource $source, bool $force): SyncResult {
		$now = $this->timeFactory->getTime();
		$state = $this->states->get($source->id);
		$state->attemptAt = $now;
		$state->firstAttemptAt ??= $now;
		try {
			$response = $this->download($source, $state, $force);
			if ($response === null) {
				$state->successAt = $now;
				$state->error = null;
				$state->errorStatus = null;
				$state->failures = 0;
				$this->states->save($source->id, $state);
				return new SyncResult($source->id, SyncResult::UNCHANGED, ranges: $state->ranges);
			}
			$parsed = $this->parse($source, $this->readBody($response));
			$merged = RangeCodec::merge($parsed->ranges);
			$parsed->ranges = [];

			$version = max($this->ranges->maxVersion($source->id), $state->version ?? 0, $state->previous ?? 0) + 1;
			$this->ranges->writeVersion($source->id, $version, $merged);

			$state->previous = $state->version;
			$state->version = $version;
			$state->switchedAt = $now;
			$state->ranges = count($merged);
			$state->entries = $parsed->entries;
			$state->skipped = $parsed->skipped;
			$state->malformed = $parsed->malformed;
			$state->successAt = $now;
			$state->error = null;
			$state->errorStatus = null;
			$state->failures = 0;
			$state->url = $source->url;
			$state->lastModified = self::headerValue($response, 'Last-Modified');
			$state->etag = self::headerValue($response, 'ETag');
			$this->states->save($source->id, $state);

			$this->ranges->deleteVersionsExcept($source->id, self::kept($state));
			return new SyncResult($source->id, SyncResult::UPDATED, ranges: $state->ranges);
		} catch (SyncFailure $e) {
			return $this->failed($source, $state, $now, $e->reason, $e->getMessage(), $e->status);
		} catch (\Throwable $e) {
			// The HTTP client may wrap a failure raised in the sink or a callback.
			$previous = $e->getPrevious();
			if ($previous instanceof SyncFailure) {
				return $this->failed($source, $state, $now, $previous->reason, $previous->getMessage(), $previous->status);
			}
			$this->logger->warning('Intrusion detection could not sync the list {list}', ['list' => $source->id, 'exception' => $e]);
			return $this->failed($source, $state, $now, SyncFailure::NETWORK, $e->getMessage());
		}
	}

	private function failed(BlocklistSource $source, ListState $state, int $now, string $reason, string $detail, ?int $status = null): SyncResult {
		$this->logger->info('Intrusion detection did not take the list {list}: {detail}', ['list' => $source->id, 'detail' => $detail]);
		$state->failureAt = $now;
		$state->error = $reason;
		$state->errorStatus = $status;
		$state->failures++;
		$this->states->save($source->id, $state);
		return new SyncResult($source->id, SyncResult::FAILED, $reason, $state->ranges, $status);
	}

	/**
	 * @return ?IResponse null when the publisher reports no change
	 * @throws SyncFailure
	 */
	private function download(BlocklistSource $source, ListState $state, bool $force): ?IResponse {
		if (!$this->urlPolicy->isAllowed($source->url)) {
			throw new SyncFailure(SyncFailure::URL_REFUSED);
		}
		$headers = ['Accept' => '*/*'];
		$conditional = !$force && $state->version !== null && $state->url === $source->url;
		if ($conditional && $state->lastModified !== null) {
			$headers['If-Modified-Since'] = $state->lastModified;
		}
		if ($conditional && $state->etag !== null) {
			$headers['If-None-Match'] = $state->etag;
		}
		$response = $this->clientService->newClient()->get($source->url, [
			'headers' => $headers,
			'timeout' => self::TIMEOUT,
			'connect_timeout' => self::CONNECT_TIMEOUT,
			'http_errors' => false,
			// The body goes into a sink that aborts the transfer at MAX_BYTES;
			// a declared length above it is refused before the body is read.
			'sink' => new LimitedSink(self::MAX_BYTES),
			'on_headers' => static function (ResponseInterface $response): void {
				$length = $response->getHeaderLine('Content-Length');
				if ($length !== '' && ctype_digit($length) && (int)$length > self::MAX_BYTES) {
					throw new SyncFailure(SyncFailure::TOO_LARGE);
				}
			},
			// Replaces the client's default redirect handling, so every hop is
			// checked here like the list address itself.
			'allow_redirects' => [
				'max' => self::MAX_REDIRECTS,
				'strict' => true,
				'referer' => false,
				'protocols' => ['https'],
				'on_redirect' => function (mixed $request, mixed $response, UriInterface $uri): void {
					if (!$this->urlPolicy->isAllowed((string)$uri)) {
						throw new SyncFailure(SyncFailure::URL_REFUSED, 'redirect');
					}
				},
			],
		]);
		$status = $response->getStatusCode();
		if ($status === 304 && $conditional) {
			return null;
		}
		if ($status !== 200) {
			throw new SyncFailure(SyncFailure::HTTP, (string)$status, $status);
		}
		return $response;
	}

	/**
	 * The body the sink collected. The limit is checked again here, for
	 * clients that hand the body over differently.
	 *
	 * @throws SyncFailure
	 */
	private function readBody(IResponse $response): string {
		$length = $response->getHeader('Content-Length');
		if ($length !== '' && ctype_digit($length) && (int)$length > self::MAX_BYTES) {
			throw new SyncFailure(SyncFailure::TOO_LARGE);
		}
		$body = $response->getBody();
		if (is_resource($body)) {
			$body = stream_get_contents($body, self::MAX_BYTES + 1);
		}
		if (!is_string($body)) {
			throw new SyncFailure(SyncFailure::NETWORK, 'no body');
		}
		if (strlen($body) > self::MAX_BYTES) {
			throw new SyncFailure(SyncFailure::TOO_LARGE);
		}
		return $body;
	}

	/**
	 * @throws SyncFailure
	 */
	private function parse(BlocklistSource $source, string $body): ParsedList {
		try {
			$parsed = $source->format->parser()->parse($body);
		} catch (ListFormatException $e) {
			throw new SyncFailure(SyncFailure::INVALID_FORMAT, $e->getMessage());
		}
		if ($parsed->entries > self::MAX_ENTRIES) {
			throw new SyncFailure(SyncFailure::TOO_MANY_ENTRIES, $parsed->entries . ' > ' . self::MAX_ENTRIES);
		}
		if ($parsed->malformedShare() > self::MAX_MALFORMED_SHARE) {
			throw new SyncFailure(SyncFailure::TOO_MANY_MALFORMED, $parsed->malformed . ' of ' . ($parsed->entries + $parsed->malformed));
		}
		if ($parsed->entries === 0) {
			throw new SyncFailure(SyncFailure::EMPTY);
		}
		return $parsed;
	}

	private function cleanupLocked(int $now): void {
		$enabled = [];
		foreach ($this->sources->enabled() as $source) {
			$enabled[$source->id] = true;
		}
		foreach ($this->ranges->listIds() as $id) {
			if (!isset($enabled[$id])) {
				$this->ranges->deleteVersionsExcept($id, []);
			}
		}
		foreach ($this->states->all() as $id => $state) {
			if (!isset($enabled[$id])) {
				if ($this->sources->get($id) === null) {
					$this->states->remove($id);
					$this->stats->deleteList($id);
				} elseif ($state->version !== null) {
					// Switched off: the rows are gone, the sync history stays.
					$state->version = null;
					$state->previous = null;
					$state->ranges = 0;
					$this->states->save($id, $state);
				}
				continue;
			}
			if ($state->previous !== null && $state->switchedAt !== null && $now - $state->switchedAt >= self::PREVIOUS_GRACE) {
				$state->previous = null;
				$this->states->save($id, $state);
			}
			// Also removes what a sync that died half-way left behind.
			$this->ranges->deleteVersionsExcept($id, self::kept($state));
		}
		$this->stats->deleteBefore(gmdate('Y-m-d', $now - self::STATS_DAYS * 86400));
	}

	/**
	 * @return list<int> the versions of a list that must stay
	 */
	private static function kept(ListState $state): array {
		return array_values(array_filter([$state->version, $state->previous], static fn (?int $v): bool => $v !== null));
	}

	private static function headerValue(IResponse $response, string $name): ?string {
		$value = trim($response->getHeader($name));
		return $value === '' || strlen($value) > 200 ? null : $value;
	}
}
