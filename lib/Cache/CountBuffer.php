<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Cache;

use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IMemcache;
use Psr\Log\LoggerInterface;

/**
 * Counters that many requests raise at the same moment, kept in the memory
 * cache and written to the database in batches: the failed logins per
 * account and day, the matches per blocklist and day, and the hits of a
 * detection. Written one by one, each event would update the same row from
 * every web server at once.
 *
 * - An event costs three to seven cache operations and no query. Counts are
 *   kept per member (an account, a list, a detection) and minute, with the
 *   time of the last event and up to MAX_DETAILS details (addresses) with
 *   their last time. Each minute lists its members, so that a flush finds
 *   them. Keys hold members and details as keyed hashes
 *   ({@see Fingerprinter::lookup()}); the lists of members and details hold
 *   them in clear, as the tables they are written to do.
 * - A flush writes every minute that ended at least SETTLE seconds ago, one
 *   write per member and minute, and then removes it from the cache. The
 *   cleanup job flushes every five minutes, and a web request with a
 *   verdict miss at most every FLUSH_INTERVAL seconds ({@see flushIfDue()}):
 *   that also writes the counts of a cache each web server keeps for itself
 *   (APCu). A flush in a web request writes at most REQUEST_BUDGET members.
 *   {@see \OCA\IntrusionDetection\BackgroundJob\PendingCounts} names the owners.
 * - The tables lag behind by up to FLUSH_INTERVAL plus two minutes; with a
 *   cache per web server, until that server's next flush. Readers that need
 *   the latest count add what still waits in the cache ({@see pending()}).
 * - An owner may take a member's counts to write them with its own write
 *   ({@see take()}); a count is claimed with an atomic compare-and-delete
 *   by whoever takes or writes it, so it is written once.
 * - When the cache is emptied or restarted, the counts it holds are lost:
 *   those since the last flush. So is an event whose write landed more than
 *   SETTLE seconds after its minute ended.
 * - Without a memory cache that outlives the request, {@see count()}
 *   returns false and the owner writes the event itself.
 *
 * @psalm-type PendingCount = array{start: int, count: int, last: int, details: array<string, int>}
 */
class CountBuffer {
	/** Counts are kept per minute */
	public const PERIOD = 60;
	/** How often a web request writes the counts */
	public const FLUSH_INTERVAL = 300;
	/** A minute is written once it ended this long ago, so that its writes have landed */
	public const SETTLE = 10;
	/** How long counts wait in the cache for a flush */
	public const TTL = 86400;
	/** Details kept per member and minute; a further new one replaces the oldest */
	public const MAX_DETAILS = 20;
	/** Members a flush in a web request writes at most */
	public const REQUEST_BUDGET = 20;
	/** The namespace in {@see Caches} */
	public const CACHE = 'counts';
	/** Minutes looked back without a cursor, and by a reader at most */
	private const LOOK_BACK = 60;
	private const LOCK_TTL = 120;
	/** Core's cache that lives only as long as the request, which installs without a configured cache get in tests */
	private const REQUEST_ONLY = 'OC\\Memcache\\ArrayCache';

	/** Members the running flush may still write */
	private int $budget = 0;

	public function __construct(
		private readonly Caches $caches,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
		private readonly Fingerprinter $fingerprinter,
	) {
	}

	/**
	 * Count one event of a member, with an optional detail such as the
	 * address.
	 *
	 * @param string $buffer the owner's name for its counts
	 * @return bool false when there is no memory cache: then the caller writes the event itself
	 */
	public function count(string $buffer, string $member, ?string $detail = null): bool {
		$cache = $this->cache();
		if ($cache === null) {
			return false;
		}
		$now = $this->timeFactory->getTime();
		$period = intdiv($now, self::PERIOD);
		$base = $this->base($buffer, $period, $member);
		if ($cache->add($base . '/c', 1, self::TTL)) {
			$slot = $this->next($cache, $buffer . '/' . $period . '/n');
			$cache->set($buffer . '/' . $period . '/m/' . $slot, $member, self::TTL);
		} elseif ($cache->inc($base . '/c') === false) {
			return false;
		}
		$cache->set($base . '/t', $now, self::TTL);
		if ($detail !== null) {
			$key = $base . '/e/' . $this->hash($detail);
			if ($cache->add($key, $now, self::TTL)) {
				$slot = $this->next($cache, $base . '/k');
				$cache->set($base . '/d/' . (($slot - 1) % self::MAX_DETAILS), $detail, self::TTL);
			} else {
				$cache->set($key, $now, self::TTL);
			}
		}
		return true;
	}

	/**
	 * What still waits in the cache for one member, from the minutes not
	 * written yet. With a cache per web server, this server's only.
	 *
	 * @return list<PendingCount> oldest first
	 */
	public function pending(string $buffer, string $member): array {
		$cache = $this->cache();
		if ($cache === null) {
			return [];
		}
		$current = intdiv($this->timeFactory->getTime(), self::PERIOD);
		$pending = [];
		for ($period = max(self::int($cache->get($buffer . '/cursor')), $current - self::LOOK_BACK); $period <= $current; $period++) {
			$base = $this->base($buffer, $period, $member);
			$count = self::int($cache->get($base . '/c'));
			if ($count > 0) {
				$pending[] = $this->read($cache, $base, $period, $count)[0];
			}
		}
		return $pending;
	}

	/**
	 * Take what waits in the cache for one member, from the minutes not
	 * written yet, so that the caller writes it itself: how many, and the
	 * time of the last. Each count is taken or written once; one raised
	 * while it is taken stays for a later flush. With a cache per web
	 * server, this server's only.
	 *
	 * @return array{0: int, 1: int}
	 */
	public function take(string $buffer, string $member): array {
		$cache = $this->cache();
		if ($cache === null) {
			return [0, 0];
		}
		$current = intdiv($this->timeFactory->getTime(), self::PERIOD);
		$taken = 0;
		$last = 0;
		for ($period = max(self::int($cache->get($buffer . '/cursor')), $current - self::LOOK_BACK); $period <= $current; $period++) {
			$base = $this->base($buffer, $period, $member);
			$count = self::int($cache->get($base . '/c'));
			if ($count <= 0) {
				continue;
			}
			$at = self::int($cache->get($base . '/t'));
			if ($cache->cad($base . '/c', $count)) {
				$taken += $count;
				$last = max($last, $at);
			}
		}
		return [$taken, $last];
	}

	/**
	 * Flush when the last flush in a web request is FLUSH_INTERVAL ago.
	 * Costs one cache operation otherwise, and never throws.
	 *
	 * @param \Closure(): list<\Closure(): bool> $writers built only when due
	 */
	public function flushIfDue(\Closure $writers): void {
		try {
			$cache = $this->cache();
			if ($cache === null || !$cache->add('due', 1, self::FLUSH_INTERVAL)) {
				return;
			}
			if (!$this->flush($writers(), self::REQUEST_BUDGET)) {
				// The next request continues.
				$cache->remove('due');
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not write the counts kept in the memory cache', ['exception' => $e]);
		}
	}

	/**
	 * Write counts with the owners' writers, in their order, at most
	 * `$budget` members. A writer calls {@see drain()} for its counts and
	 * returns its result. Only one flush runs at a time per cache; another
	 * one returns at once.
	 *
	 * @param list<\Closure(): bool> $writers
	 * @param-out int $written
	 * @return bool false when some are left
	 */
	public function flush(array $writers, int $budget = PHP_INT_MAX, ?int &$written = 0): bool {
		$written = 0;
		$cache = $this->cache();
		if ($cache === null || !$cache->add('lock', 1, self::LOCK_TTL)) {
			return true;
		}
		$this->budget = $budget;
		$done = true;
		try {
			foreach ($writers as $write) {
				try {
					$done = $write() && $done;
				} catch (\Throwable $e) {
					$done = false;
					$this->logger->error('Intrusion detection could not write counts kept in the memory cache', ['exception' => $e]);
				}
			}
		} finally {
			$written = $budget - $this->budget;
			$this->budget = 0;
			$cache->remove('lock');
		}
		return $done;
	}

	/**
	 * Write the counts of one owner, during {@see flush()}: `$write` gets
	 * each member with its counts of one minute, the oldest minute first.
	 * A member is removed from the cache once `$write` returned; when it
	 * throws, the member stays for the next flush.
	 *
	 * @param \Closure(string, PendingCount): void $write
	 * @return bool false when the flush's budget ran out first
	 */
	public function drain(string $buffer, \Closure $write): bool {
		$cache = $this->cache();
		if ($cache === null) {
			return true;
		}
		$last = intdiv($this->timeFactory->getTime() - self::SETTLE, self::PERIOD) - 1;
		$cursorKey = $buffer . '/cursor';
		$cursor = self::int($cache->get($cursorKey));
		$period = max($cursor === 0 ? $last - self::LOOK_BACK : $cursor, $last - intdiv(self::TTL, self::PERIOD));
		for (; $period <= $last; $period++) {
			$prefix = $buffer . '/' . $period;
			$members = self::int($cache->get($prefix . '/n'));
			for ($slot = 1; $slot <= $members; $slot++) {
				$member = $cache->get($prefix . '/m/' . $slot);
				if (!is_string($member)) {
					continue;
				}
				$base = $this->base($buffer, $period, $member);
				$count = self::int($cache->get($base . '/c'));
				if ($count <= 0) {
					// Written by an earlier flush that stopped within this minute, or taken.
					continue;
				}
				if ($this->budget <= 0) {
					$cache->set($cursorKey, $period, self::TTL);
					return false;
				}
				[$pending, $keys] = $this->read($cache, $base, $period, $count);
				if (!$cache->cad($base . '/c', $count)) {
					// Taken in the meantime ({@see take()}).
					continue;
				}
				$this->budget--;
				try {
					$write($member, $pending);
				} catch (\Throwable $e) {
					$this->restore($cache, $base . '/c', $count);
					throw $e;
				}
				foreach ($keys as $key) {
					$cache->remove($key);
				}
			}
			for ($slot = 1; $slot <= $members; $slot++) {
				$cache->remove($prefix . '/m/' . $slot);
			}
			$cache->remove($prefix . '/n');
		}
		$cache->set($cursorKey, $period, self::TTL);
		return true;
	}

	/**
	 * The cache, unless it forgets the counts at the end of the request.
	 */
	private function cache(): ?IMemcache {
		$cache = $this->caches->shared(self::CACHE);
		return $cache === null || ltrim($cache::class, '\\') === self::REQUEST_ONLY ? null : $cache;
	}

	/**
	 * @return array{0: PendingCount, 1: list<string>} the counts, and the keys besides the count that hold them
	 */
	private function read(IMemcache $cache, string $base, int $period, int $count): array {
		$start = $period * self::PERIOD;
		$keys = [$base . '/t', $base . '/k'];
		$details = [];
		$slots = min(self::MAX_DETAILS, self::int($cache->get($base . '/k')));
		for ($i = 0; $i < $slots; $i++) {
			$keys[] = $base . '/d/' . $i;
			$detail = $cache->get($base . '/d/' . $i);
			if (is_string($detail)) {
				$keys[] = $base . '/e/' . $this->hash($detail);
				$details[$detail] = max($start, self::int($cache->get($base . '/e/' . $this->hash($detail))));
			}
		}
		asort($details);
		return [
			['start' => $start, 'count' => $count, 'last' => max($start, self::int($cache->get($base . '/t'))), 'details' => $details],
			$keys,
		];
	}

	/**
	 * Put a count back that could not be written.
	 */
	private function restore(IMemcache $cache, string $key, int $count): void {
		if (!$cache->add($key, $count, self::TTL)) {
			$cache->inc($key, $count);
		}
	}

	/**
	 * The next number of a counter that lives as long as the counts.
	 */
	private function next(IMemcache $cache, string $key): int {
		return $cache->add($key, 1, self::TTL) ? 1 : self::int($cache->inc($key));
	}

	private function base(string $buffer, int $period, string $member): string {
		return $buffer . '/' . $period . '/' . $this->hash($member);
	}

	/**
	 * A keyed hash of an account or address for a cache key, 128 bits.
	 */
	private function hash(string $value): string {
		return substr($this->fingerprinter->lookup($value), 0, 32);
	}

	private static function int(mixed $value): int {
		return is_int($value) ? $value : (is_numeric($value) ? (int)$value : 0);
	}
}
