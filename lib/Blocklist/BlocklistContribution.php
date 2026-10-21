<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\DecoyCredential;
use OCA\IntrusionDetection\Check\Checks\ReservedName;
use OCA\IntrusionDetection\Check\Checks\TrapUrl;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Http\Client\IClientService;
use OCP\Security\Bruteforce\IThrottler;
use Psr\Log\LoggerInterface;

/**
 * Builds and sends the reports for the shared blocklist.
 *
 * Reported are the addresses blocked by the checks with near-zero false
 * positives (decoy credentials, trap URLs, reserved names) since the last
 * successful run: only blocks of enforced detections that were not lifted,
 * never private, loopback, link-local or otherwise reserved addresses
 * ({@see RangeCodec::RESERVED}), never addresses on the brute-force
 * allowlist, and at most MAX_REPORTS per run. The job runs daily.
 *
 * The payload is `{instance, version, reports: [{ip, check, first_seen, hits}]}`
 * and nothing else: no user, no user agent, nothing from the detection's
 * explanation. `instance` is a random id ({@see ContributionSettings::contributorId()}).
 * IPv4 addresses are sent as the address, IPv6 as the blocked /64.
 */
class BlocklistContribution {
	public const CHECKS = [DecoyCredential::ID, TrapUrl::ID, ReservedName::ID];

	/** Version of the payload format */
	public const FORMAT_VERSION = 1;
	public const MAX_REPORTS = 1000;
	/** Ban rows read per run: more than MAX_REPORTS, because rows are merged or left out */
	public const MAX_ROWS = 5000;
	/** The first window, before any successful run */
	public const FIRST_WINDOW = 86400;
	/** Blocks older than this are not reported, however long the service was unreachable */
	public const MAX_WINDOW = 7 * 86400;
	public const MAX_RESPONSE_BYTES = 8192;
	private const TIMEOUT = 30;
	private const CONNECT_TIMEOUT = 10;

	public function __construct(
		private readonly ContributionSettings $config,
		private readonly Settings $settings,
		private readonly BanMapper $bans,
		private readonly IThrottler $throttler,
		private readonly IClientService $clientService,
		private readonly UrlPolicy $urlPolicy,
		private readonly AuditLogger $audit,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * Exactly what the job would send if it ran now, or why it would not.
	 */
	public function preview(): ContributionBatch {
		return $this->build($this->timeFactory->getTime());
	}

	/**
	 * Send the next batch and record the outcome. The window only moves on
	 * when the service accepted the reports, or when there was nothing to send.
	 */
	public function send(): ContributionBatch {
		$now = $this->timeFactory->getTime();
		$batch = $this->build($now);
		if (in_array($batch->reason, [ContributionBatch::REASON_UNAVAILABLE, ContributionBatch::REASON_DISABLED, ContributionBatch::REASON_PROTECTION_OFF], true)) {
			return $batch;
		}
		$state = $this->config->state();
		$state->attemptAt = $now;
		if ($batch->reason === ContributionBatch::REASON_NOTHING_NEW) {
			$this->succeeded($state, $batch, ContributionState::RESULT_NOTHING, 0);
			return $batch;
		}
		if ($batch->reason !== null) {
			$this->failed($state, $batch, $batch->reason);
			return $batch;
		}

		$url = $this->config->url();
		$reports = count($batch->payload['reports'] ?? []);
		try {
			$response = $this->clientService->newClient()->post($url, [
				'body' => $batch->body(),
				'headers' => ['Content-Type' => 'application/json', 'Accept' => 'application/json'],
				'timeout' => self::TIMEOUT,
				'connect_timeout' => self::CONNECT_TIMEOUT,
				'allow_redirects' => false,
				'http_errors' => false,
				// Aborts the transfer when the answer is larger than expected.
				'sink' => new LimitedSink(self::MAX_RESPONSE_BYTES),
			]);
			$status = $response->getStatusCode();
		} catch (\Throwable $e) {
			$tooLarge = ($e instanceof SyncFailure ? $e : $e->getPrevious()) instanceof SyncFailure;
			$this->logger->warning('Intrusion detection could not send the shared blocklist reports', ['exception' => $e]);
			$this->failed($state, $batch, $tooLarge ? 'response_too_large' : 'network');
			return $batch;
		}
		if ($status < 200 || $status >= 300) {
			$this->logger->info('The shared blocklist service answered {status}', ['status' => $status]);
			$this->failed($state, $batch, 'http_' . $status);
			return $batch;
		}
		$this->succeeded($state, $batch, ContributionState::RESULT_SENT, $reports);
		$this->audit->log('shared blocklist contribution sent %s reports to %s', ['reports' => $reports, 'url' => $url]);
		return $batch;
	}

	private function build(int $now): ContributionBatch {
		if (!$this->config->isAvailable()) {
			return new ContributionBatch(null, ContributionBatch::REASON_UNAVAILABLE, $now, $now);
		}
		$state = $this->config->state();
		$start = max($state->windowEnd ?? $now - self::FIRST_WINDOW, $now - self::MAX_WINDOW);
		[$reports, $truncated] = $this->reports($start, $now);
		$payload = [
			'instance' => $this->config->contributorId(),
			'version' => self::FORMAT_VERSION,
			'reports' => $reports,
		];
		$url = $this->config->url();
		$reason = match (true) {
			!$this->config->isEnabled() => ContributionBatch::REASON_DISABLED,
			!$this->settings->isEnabled() => ContributionBatch::REASON_PROTECTION_OFF,
			$url === '' => ContributionBatch::REASON_NO_URL,
			!$this->urlPolicy->isAllowed($url) => ContributionBatch::REASON_URL_REFUSED,
			$reports === [] => ContributionBatch::REASON_NOTHING_NEW,
			default => null,
		};
		return new ContributionBatch($payload, $reason, $start, $now, $truncated);
	}

	/**
	 * One report per address and check: first seen is the earliest of its
	 * detections, hits their sum.
	 *
	 * @return array{0: list<array{ip: string, check: string, first_seen: int, hits: int}>, 1: bool} the reports, and whether some were left for lack of room
	 */
	private function reports(int $after, int $until): array {
		$rows = $this->bans->findForContribution(self::CHECKS, $after, $until, self::MAX_ROWS);
		$truncated = count($rows) >= self::MAX_ROWS;
		$reports = [];
		$counted = [];
		foreach ($rows as $row) {
			$ip = $this->reportedAddress($row['cidr'], $row['detectionIp']);
			if ($ip === null) {
				continue;
			}
			$key = $ip . ' ' . $row['checkId'];
			if (!isset($reports[$key])) {
				if (count($reports) >= self::MAX_REPORTS) {
					$truncated = true;
					break;
				}
				$reports[$key] = ['ip' => $ip, 'check' => $row['checkId'], 'first_seen' => $row['firstSeen'], 'hits' => 0];
			}
			// One detection can lead to several bans; its hits count once.
			if (!isset($counted[$key][$row['detectionId']])) {
				$counted[$key][$row['detectionId']] = true;
				$reports[$key]['first_seen'] = min($reports[$key]['first_seen'], $row['firstSeen']);
				$reports[$key]['hits'] += max(1, $row['hits']);
			}
		}
		return [array_values($reports), $truncated];
	}

	/**
	 * The address as reported, or null when it must not leave the server.
	 */
	private function reportedAddress(string $cidr, ?string $detectionIp): ?string {
		try {
			$range = RangeCodec::parse($cidr);
		} catch (\InvalidArgumentException) {
			return null;
		}
		if (RangeCodec::overlapsReserved($range['family'], $range['start'], $range['end'])) {
			return null;
		}
		$first = RangeCodec::hexToAddress($range['start'], $range['family']);
		if (filter_var($first, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
			return null;
		}
		if ($this->throttler->isBypassListed($first)) {
			return null;
		}
		// The allowlist may name a single IPv6 address inside a blocked /64.
		$source = $detectionIp === null ? null : SourceKey::tryFromIp($detectionIp);
		if ($source !== null && $source->ip !== $first && $source->netKey === $cidr && $this->throttler->isBypassListed($source->ip)) {
			return null;
		}
		return $range['start'] === $range['end'] ? $first : RangeCodec::format($range['family'], $range['start'], $range['end']);
	}

	private function succeeded(ContributionState $state, ContributionBatch $batch, string $result, int $reports): void {
		$state->successAt = $state->attemptAt;
		$state->windowEnd = $batch->windowEnd;
		$state->result = $result;
		$state->error = null;
		$state->reports = $reports;
		$this->config->saveState($state);
	}

	/**
	 * The window stays where it was. Before the first success its start is
	 * fixed now, so failed runs do not lose the blocks of the first day.
	 */
	private function failed(ContributionState $state, ContributionBatch $batch, string $error): void {
		$state->windowEnd ??= $batch->windowStart;
		$state->result = ContributionState::RESULT_FAILED;
		$state->error = $error;
		$this->config->saveState($state);
	}
}
