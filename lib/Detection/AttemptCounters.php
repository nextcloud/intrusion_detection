<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCP\IMemcache;

/**
 * Counts the failed logins (passwords and app passwords) per address, IPv4
 * network, account and password fingerprint in the distributed cache, in
 * buckets of WINDOW seconds by the time of the attempt. The buckets around
 * a time hold every failed login of the WINDOW before it, so their sum is an
 * upper bound of what a count over the attempts table finds in the window
 * of any check: none is longer than WINDOW. A detector skips such a count
 * while the bound stays below the lowest limit the count could reach
 * ({@see mayReach()}): no failure, no distinct address and no distinct
 * name can be counted more often than there were failed logins.
 *
 * - The bound only holds for counters the cache kept from the start. It is
 *   used once counting has run for WINDOW (the `since` key); a cache that
 *   was restarted or emptied starts over, and counts are made in the
 *   database until then.
 * - With a cache of each web server only (APCu), a web server sees only its
 *   own failed logins, so its counts would be too low: nothing is counted,
 *   and every count is made in the database.
 * - A cache that evicts keys before they expire, under memory pressure,
 *   can make a bound too low. The counters are small and touched on every
 *   failed login, so they are the last to go.
 */
class AttemptCounters {
	/** The size of a bucket: as long as attempts are kept, and so as the longest window of a check */
	public const WINDOW = AttemptRecorder::RETENTION;
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'attempt-counters';
	public const KINDS = [AttemptKind::PasswordLogin, AttemptKind::AppPassword];
	/** The start of counting is kept this long; once it expires, counting starts over */
	private const SINCE_TTL = 30 * 86400;

	public function __construct(
		private readonly Caches $caches,
	) {
	}

	/**
	 * Count a failed login that was stored.
	 */
	public function count(#[\SensitiveParameter] AttemptRecord $attempt): void {
		$cache = $this->cache();
		if ($cache === null || !$attempt->stored || !in_array($attempt->kind, self::KINDS, true)) {
			return;
		}
		// Added before the first counter: counting never claims to have started later than it did.
		$cache->add('since', $attempt->time, self::SINCE_TTL);
		$bucket = intdiv($attempt->time, self::WINDOW);
		foreach (['ip_key' => $attempt->source->ipKey, 'net_key' => $attempt->source->netKey, 'uid' => $attempt->uid, 'pw_fp' => $attempt->passwordFingerprint] as $column => $value) {
			if ($value === null) {
				continue;
			}
			$key = self::key($column, $value, $bucket);
			if (!$cache->add($key, 1, 3 * self::WINDOW)) {
				$cache->inc($key);
			}
		}
	}

	/**
	 * Whether the failed logins whose column has one of the values within
	 * WINDOW before a time can reach a number: always, without a bound.
	 *
	 * @param 'ip_key'|'net_key'|'uid'|'pw_fp' $column
	 * @param list<string> $values
	 */
	public function mayReach(string $column, #[\SensitiveParameter] array $values, int $now, int $needed): bool {
		$bound = $this->bound($column, $values, $now);
		return $bound === null || $bound >= $needed;
	}

	/**
	 * An upper bound of the failed logins whose column has one of the values
	 * within WINDOW before a time, or null when there is none.
	 *
	 * @param 'ip_key'|'net_key'|'uid'|'pw_fp' $column
	 * @param list<string> $values
	 */
	public function bound(string $column, #[\SensitiveParameter] array $values, int $now): ?int {
		$cache = $this->cache();
		$since = $cache?->get('since');
		if ($cache === null || !is_int($since) || $since > $now - self::WINDOW) {
			return null;
		}
		$bucket = intdiv($now, self::WINDOW);
		$bound = 0;
		foreach ($values as $value) {
			// The next bucket too: another web server's clock may be ahead.
			foreach ([$bucket - 1, $bucket, $bucket + 1] as $b) {
				$count = $cache->get(self::key($column, $value, $b));
				$bound += is_int($count) ? $count : 0;
			}
		}
		return $bound;
	}

	private function cache(): ?IMemcache {
		return $this->caches->isDistributed() ? $this->caches->shared(self::CACHE) : null;
	}

	private static function key(string $column, string $value, int $bucket): string {
		// Hashed, so that no account name or address is part of a cache key.
		return hash('sha256', $column . "\0" . $value) . '/' . $bucket;
	}
}
