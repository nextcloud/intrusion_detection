<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Breach;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Blocklist\LimitedSink;
use OCP\Http\Client\IClientService;
use OCP\ICache;
use OCP\ICacheFactory;
use OCP\Security\ICrypto;
use Psr\Log\LoggerInterface;

/**
 * Asks the Pwned Passwords service of Have I Been Pwned how often a password
 * appears in published breaches, without revealing it (k-anonymity).
 *
 * - The SHA-1 of the password is computed in memory. Only its first 5 hex
 *   characters are sent; the service answers with every known hash suffix of
 *   that range and the comparison happens here. With `Add-Padding`, the
 *   answer is padded with fake entries (count 0), so its size does not reveal
 *   the range either.
 * - The password, its hash and the prefix are never stored or logged.
 * - Answers are public data, cached per range for a day in the memory cache
 *   (distributed if available, else local; never in the database). The cache
 *   key is a keyed hash of the prefix and the cached range is encrypted with
 *   the instance secret, so reading the cache does not reveal which ranges
 *   were asked for.
 * - Fails open: a timeout, an error status or a malformed answer gives null.
 */
class PwnedPasswordsClient {
	public const RANGE_URL = 'https://api.pwnedpasswords.com/range/';
	/** Seconds for the whole request, including the connection */
	public const TIMEOUT = 2;
	/** A padded range has about 1 000 lines of 40 bytes; anything far larger is refused */
	public const MAX_BYTES = 512 * 1024;
	public const CACHE_TTL = 86400;
	public const PREFIX_LENGTH = 5;

	/** A hash suffix and its count; the count has at most 12 digits */
	private const LINE = '/^([0-9A-F]{35}):(\d{1,12})$/';
	private const CACHE_KEY_PREFIX = 'hibp:';

	private ?ICache $cache = null;
	private bool $cacheInitialised = false;

	public function __construct(
		private readonly IClientService $clientService,
		private readonly ICacheFactory $cacheFactory,
		private readonly ICrypto $crypto,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * How often the password appears in the breach list: 0 when it does not,
	 * null when the service could not be asked.
	 */
	public function count(#[\SensitiveParameter] string $password): ?int {
		$hash = strtoupper(sha1($password));
		$range = $this->range(substr($hash, 0, self::PREFIX_LENGTH));
		if ($range === null) {
			return null;
		}
		return $range[substr($hash, self::PREFIX_LENGTH)] ?? 0;
	}

	/**
	 * The suffixes of one range with a count above 0, from the cache or the service.
	 *
	 * @return ?array<string, int>
	 */
	private function range(#[\SensitiveParameter] string $prefix): ?array {
		$cached = $this->readCache($prefix);
		if ($cached !== null) {
			return $cached;
		}
		$body = $this->fetch($prefix);
		$range = $body === null ? null : self::parse($body);
		if ($range === null) {
			return null;
		}
		$this->writeCache($prefix, $range);
		return $range;
	}

	private function fetch(#[\SensitiveParameter] string $prefix): ?string {
		try {
			$response = $this->clientService->newClient()->get(self::RANGE_URL . $prefix, [
				'headers' => ['Add-Padding' => 'true', 'Accept' => 'text/plain'],
				'timeout' => self::TIMEOUT,
				'connect_timeout' => self::TIMEOUT,
				'allow_redirects' => false,
				'http_errors' => false,
				// Aborts the transfer when the answer grows beyond MAX_BYTES.
				'sink' => new LimitedSink(self::MAX_BYTES),
			]);
			$status = $response->getStatusCode();
			$body = $status === 200 ? $response->getBody() : null;
			if (is_resource($body)) {
				$body = stream_get_contents($body, self::MAX_BYTES + 1);
			}
		} catch (\Throwable $e) {
			// Exception messages name the requested address, which holds the
			// prefix: only the kind of failure is logged.
			$this->logger->warning('Intrusion detection could not reach the breached password service ({error}); the password is checked at the next login', [
				'error' => get_class($e),
			]);
			return null;
		}
		if ($status !== 200) {
			$this->logger->warning('The breached password service answered {status}; the password is checked at the next login', ['status' => $status]);
			return null;
		}
		if (!is_string($body) || strlen($body) > self::MAX_BYTES) {
			$this->logger->warning('The breached password service sent an unusable answer; the password is checked at the next login');
			return null;
		}
		return $body;
	}

	/**
	 * Parse `SUFFIX:COUNT` lines. Padding lines (count 0) are dropped, other
	 * lines that do not match are ignored. An answer without a single valid
	 * line is not a range answer.
	 *
	 * @return ?array<string, int>
	 */
	public static function parse(string $body): ?array {
		$range = [];
		$valid = 0;
		foreach (explode("\n", $body) as $line) {
			if (preg_match(self::LINE, rtrim($line, "\r"), $m) !== 1) {
				continue;
			}
			$valid++;
			$count = (int)$m[2];
			if ($count > 0) {
				$range[$m[1]] = $count;
			}
		}
		return $valid === 0 ? null : $range;
	}

	/**
	 * @return ?array<string, int>
	 */
	private function readCache(#[\SensitiveParameter] string $prefix): ?array {
		$cache = $this->cache();
		if ($cache === null) {
			return null;
		}
		try {
			$stored = $cache->get($this->cacheKey($prefix));
			if (!is_string($stored) || $stored === '') {
				return null;
			}
			return self::parse($this->crypto->decrypt($stored));
		} catch (\Throwable) {
			// An unreadable entry (for example after the secret changed) is a miss.
			return null;
		}
	}

	/**
	 * @param array<string, int> $range
	 */
	private function writeCache(#[\SensitiveParameter] string $prefix, array $range): void {
		$cache = $this->cache();
		if ($cache === null) {
			return;
		}
		$lines = [];
		foreach ($range as $suffix => $count) {
			$lines[] = $suffix . ':' . $count;
		}
		// The empty range still needs one valid line to be read back as a range.
		$lines[] = str_repeat('0', 35) . ':0';
		try {
			$cache->set($this->cacheKey($prefix), $this->crypto->encrypt(implode("\n", $lines)), self::CACHE_TTL);
		} catch (\Throwable $e) {
			$this->logger->warning('Intrusion detection could not cache a breached password range ({error})', ['error' => get_class($e)]);
		}
	}

	private function cacheKey(#[\SensitiveParameter] string $prefix): string {
		return self::CACHE_KEY_PREFIX . bin2hex(substr($this->crypto->calculateHMAC('intrusion_detection/hibp/' . $prefix), 0, 16));
	}

	private function cache(): ?ICache {
		if (!$this->cacheInitialised) {
			$this->cacheInitialised = true;
			if ($this->cacheFactory->isAvailable()) {
				$this->cache = $this->cacheFactory->createDistributed(Application::APP_ID);
			} elseif ($this->cacheFactory->isLocalCacheAvailable()) {
				$this->cache = $this->cacheFactory->createLocal(Application::APP_ID);
			}
		}
		return $this->cache;
	}
}
