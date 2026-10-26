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
 * No hit is lost: a hit while the check cools down is counted for the
 * detection in the memory cache ({@see DetectionHits}). The next merge of
 * the detection adds the hits counted meanwhile and tells the responses how
 * many hits it stands for (the count in an administrator's notification);
 * the counts are written with the others otherwise ({@see CountBuffer}).
 * - With a distributed cache (Redis), the cool-down is shared by all web
 *   servers.
 * - With a cache of each web server only (APCu), each web server cools
 *   down on its own, so each one evaluates in full once per period, and
 *   writes the hits it counted.
 * - Without a memory cache, nothing cools down.
 */
class Cooldown {
	public const PERIOD = 30;
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'cooldown';

	/** @var array<string, true> the cool-downs whose period this request ended to evaluate in full, by key */
	private array $claimed = [];

	public function __construct(
		private readonly Caches $caches,
		private readonly DetectionMapper $mapper,
		private readonly DetectionHits $hits,
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
		if (!$this->hits->count($mark['id'])) {
			$this->mapper->addHits($mark['id'], 1, $now);
		}
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
	 * @param list<string> $subject
	 */
	private static function key(string $checkId, array $subject, ModeState $mode): string {
		// Hashed, so that no account name or address is part of a cache key.
		return 'mark/' . hash('sha256', implode("\0", [$checkId, ...$subject, $mode->acts() ? 'acts' : 'observes']));
	}
}
