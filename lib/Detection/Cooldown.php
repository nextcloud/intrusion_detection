<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\IPurges;
use OCP\IMemcache;

/**
 * A short cool-down of a check that fired, per check and subject (such as
 * the account, or the rule and the address). For PERIOD seconds after a
 * full evaluation stored its detection, further failures of the subject
 * skip the counts over the window, the merge under its lock and the
 * responses:
 * - the attempt is still recorded, and the hit is counted for the detection;
 * - the detector judges the current address alone, so an address that
 *   joins the attack is still blocked at once;
 * - after the period, one failure evaluates in full again, and every
 *   failure does once the limits are no longer reached.
 *
 * PERIOD is 30 seconds, like the instance-wide evaluation of credential
 * stuffing. The facts of a detection, the end of an account's protection
 * and the count in an administrator's notification are then at most 30
 * seconds behind, while an attack with 1,000 failures per second is
 * evaluated in full once per 30,000 failures instead of every time.
 *
 * No hit is lost, and the next merged hit tells the responses how many
 * hits it stands for (the count in an administrator's notification):
 * - With a distributed cache (Redis), the hits are counted in the cache,
 *   and the cool-down is shared by all web servers. The next merge of the
 *   detection adds them ({@see takeHits()}). Those after the last full
 *   evaluation of an attack are added by the cleanup job once their
 *   period is over ({@see purge()}).
 * - With a cache of each web server only (APCu), each web server cools
 *   down on its own, so each one evaluates in full once per period, and
 *   each hit is added to the detection in the database: one write, no
 *   read. That is as correct, but less effective.
 * - Without a memory cache, nothing cools down.
 */
class Cooldown implements IPurges {
	public const PERIOD = 30;
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'cooldown';
	/** Hits counted in the cache wait at most this long to be added */
	public const HITS_TTL = 3600;
	/** The cleanup job adds the hits of the cool-downs that ended in each slice of this many seconds */
	public const FLUSH_SLICE = 300;

	/** @var array<string, true> the cool-downs whose period this request ended to evaluate in full, by key */
	private array $claimed = [];

	public function __construct(
		private readonly Caches $caches,
		private readonly DetectionMapper $mapper,
	) {
	}

	/**
	 * While the check cools down for the subject: count the hit for the
	 * check's detection and return the detection's id. Null when the check
	 * evaluates in full: it did not fire for the subject within the last
	 * period, or the period is over and this request evaluates again.
	 *
	 * @param list<string> $subject
	 */
	public function cooled(string $checkId, array $subject, ModeState $mode, int $now): ?string {
		$cache = $this->caches->shared(self::CACHE);
		if ($cache === null) {
			return null;
		}
		$key = self::key($checkId, $subject, $mode);
		$mark = $cache->get($key);
		if (!is_array($mark) || !is_int($mark['until'] ?? null) || !is_string($mark['id'] ?? null) || $now >= $mark['until'] + self::PERIOD) {
			return null;
		}
		// One request evaluates again after the period; the others keep counting until it is done.
		if ($now >= $mark['until'] && $cache->add('claim/' . $key . '/' . $mark['until'], 1, self::PERIOD)) {
			$this->claimed[$key] = true;
			return null;
		}
		$this->countHit($cache, $mark['id'], $now);
		return $mark['id'];
	}

	/**
	 * A full evaluation of the subject fired: cool down for PERIOD after the
	 * detection was last seen. Without a detection (the check was off)
	 * nothing cools down.
	 *
	 * @param list<string> $subject
	 */
	public function start(string $checkId, array $subject, ModeState $mode, ?Detection $detection): void {
		$cache = $this->caches->shared(self::CACHE);
		if ($cache === null) {
			return;
		}
		$key = self::key($checkId, $subject, $mode);
		unset($this->claimed[$key]);
		if ($detection === null) {
			$cache->remove($key);
			return;
		}
		$id = (string)$detection->getId();
		$until = (int)$detection->getLastSeenAt() + self::PERIOD;
		$cache->set($key, ['until' => $until, 'id' => $id], 2 * self::PERIOD);
		if ($this->caches->isDistributed()) {
			$this->flushAfter($cache, $id, $until + self::PERIOD);
		}
	}

	/**
	 * A full evaluation of the subject no longer reached the limits: the
	 * cool-down whose period this request ended is over.
	 *
	 * @param list<string> $subject
	 */
	public function stop(string $checkId, array $subject, ModeState $mode): void {
		$key = self::key($checkId, $subject, $mode);
		if (isset($this->claimed[$key])) {
			unset($this->claimed[$key]);
			$this->caches->shared(self::CACHE)?->remove($key);
		}
	}

	/**
	 * Take the hits counted for a detection while its check cooled down:
	 * how many are still to be added to it (those in the distributed
	 * cache), and how many there were in all, for the counts that go with
	 * a merged hit. Each hit is taken once.
	 *
	 * @return array{0: int, 1: int}
	 */
	public function takeHits(string $detectionId): array {
		$cache = $this->caches->shared(self::CACHE);
		if ($cache === null) {
			return [0, 0];
		}
		[$pending] = $this->caches->isDistributed() ? $this->take($cache, 'hits/' . $detectionId) : [0];
		[$stored] = $this->take($cache, 'stored/' . $detectionId);
		return [$pending, $pending + $stored];
	}

	/**
	 * Add the hits counted in the distributed cache to the detections whose
	 * cool-down ended in a slice that is over: an attack that stopped
	 * within a period has no next merge to add them.
	 *
	 * @return int how many detections got hits
	 */
	#[\Override]
	public function purge(int $now): int {
		$cache = $this->distributed();
		if ($cache === null) {
			return 0;
		}
		$current = intdiv($now, self::FLUSH_SLICE);
		$done = $cache->get('due/done');
		$flushed = 0;
		for ($slice = max(is_int($done) ? $done : 0, $current - intdiv(self::HITS_TTL, self::FLUSH_SLICE)); $slice < $current; $slice++) {
			$count = $cache->get('due/' . $slice);
			for ($slot = 1; is_int($count) && $slot <= $count; $slot++) {
				$id = $cache->get('due/' . $slice . '/' . $slot);
				[$hits, $last] = is_string($id) ? $this->take($cache, 'hits/' . $id) : [0, 0];
				if ($hits > 0) {
					$this->mapper->addHits((string)$id, $hits, $last);
					$flushed++;
				}
			}
		}
		$cache->set('due/done', $current, self::HITS_TTL);
		return $flushed;
	}

	private function countHit(IMemcache $cache, string $detectionId, int $now): void {
		if ($this->caches->isDistributed()) {
			$this->increment($cache, 'hits/' . $detectionId);
			$cache->set('last/' . $detectionId, $now, self::HITS_TTL);
			return;
		}
		$this->mapper->addHits($detectionId, 1, $now);
		// Added already; counted for what goes with the next merged hit.
		$this->increment($cache, 'stored/' . $detectionId);
	}

	private function increment(IMemcache $cache, string $key): void {
		if (!$cache->add($key, 1, self::HITS_TTL)) {
			$cache->inc($key);
		}
	}

	/**
	 * Take a counter, and the time of its latest hit.
	 *
	 * @return array{0: int, 1: int}
	 */
	private function take(IMemcache $cache, string $key): array {
		$hits = $cache->get($key);
		// A hit counted in between makes the delete fail; all of them are taken next time.
		if (!is_int($hits) || $hits <= 0 || !$cache->cad($key, $hits)) {
			return [0, 0];
		}
		$last = $cache->get('last/' . substr($key, strpos($key, '/') + 1));
		return [$hits, is_int($last) ? $last : 0];
	}

	/**
	 * Note the detection for the cleanup job in the slice of a time, in a
	 * slot of its own: the slice's counter hands out the slots.
	 */
	private function flushAfter(IMemcache $cache, string $detectionId, int $at): void {
		$slice = 'due/' . intdiv($at, self::FLUSH_SLICE);
		$cache->add($slice, 0, self::HITS_TTL);
		$slot = $cache->inc($slice);
		if (is_int($slot)) {
			$cache->set($slice . '/' . $slot, $detectionId, self::HITS_TTL);
		}
	}

	private function distributed(): ?IMemcache {
		return $this->caches->isDistributed() ? $this->caches->shared(self::CACHE) : null;
	}

	/**
	 * @param list<string> $subject
	 */
	private static function key(string $checkId, array $subject, ModeState $mode): string {
		// Hashed, so that no account name or address is part of a cache key.
		return 'mark/' . hash('sha256', implode("\0", [$checkId, ...$subject, $mode->acts() ? 'acts' : 'observes']));
	}
}
