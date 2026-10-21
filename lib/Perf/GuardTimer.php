<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Perf;

use OCA\IntrusionDetection\AppInfo\Application;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ICacheFactory;
use OCP\IMemcache;

/**
 * Measures the request guards on 1 in SAMPLE_RATE requests and keeps hourly
 * totals (sum, count, maximum) in the memory cache, so the admin page and
 * occ can show the real cost on this server.
 *
 * Each guard wraps its work in start() and stop(); the time of all guards
 * of a sampled request is added up and recorded once, at the end of the
 * request.
 *
 * Without a memory cache nothing is measured: writing to the database to
 * measure would cost more than the guards themselves.
 */
class GuardTimer {
	public const SAMPLE_RATE = 1000;
	private const PREFIX = 'gt:';

	private ?IMemcache $cache = null;
	private bool $initialised = false;
	/** Whether this request is sampled, decided by the first guard */
	private ?bool $sampled = null;
	private int $requestNanoseconds = 0;

	public function __construct(
		private readonly ICacheFactory $cacheFactory,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * Start timing a guard.
	 *
	 * @return int|null the start time for {@see stop()}, null when this request is not measured
	 */
	public function start(): ?int {
		if ($this->sampled === null) {
			$this->sampled = $this->sample();
			if ($this->sampled) {
				register_shutdown_function($this->finish(...));
			}
		}
		return $this->sampled ? hrtime(true) : null;
	}

	public function stop(?int $start): void {
		if ($start !== null) {
			$this->requestNanoseconds += hrtime(true) - $start;
		}
	}

	/**
	 * Record the guards' time of this request. Runs at shutdown.
	 */
	public function finish(): void {
		if ($this->requestNanoseconds > 0) {
			$this->record($this->requestNanoseconds);
			$this->requestNanoseconds = 0;
		}
	}

	/**
	 * Whether this request is one of the sampled ones.
	 */
	public function sample(): bool {
		return random_int(1, self::SAMPLE_RATE) === 1 && $this->cache() !== null;
	}

	/**
	 * @param int $nanoseconds measured with hrtime(true)
	 */
	public function record(int $nanoseconds): void {
		$cache = $this->cache();
		if ($cache === null) {
			return;
		}
		$hour = intdiv($this->timeFactory->getTime(), 3600);
		$micro = max(0, intdiv($nanoseconds, 1000));
		$ttl = 26 * 3600;
		$cache->add(self::PREFIX . $hour . ':n', 0, $ttl);
		$cache->add(self::PREFIX . $hour . ':s', 0, $ttl);
		$cache->inc(self::PREFIX . $hour . ':n');
		$cache->inc(self::PREFIX . $hour . ':s', $micro);
		$max = $cache->get(self::PREFIX . $hour . ':m');
		if (!is_int($max) || $micro > $max) {
			$cache->set(self::PREFIX . $hour . ':m', $micro, $ttl);
		}
	}

	/**
	 * Average and maximum guard time over the last `$hours` hours.
	 *
	 * Only the current hour still changes: the totals of the hours before it
	 * are added up once per hour and kept, so a view reads four keys rather
	 * than three per hour.
	 *
	 * @return array{samples: int, averageMicroseconds: float, maxMicroseconds: int}|null null when nothing was measured
	 */
	public function summary(int $hours = 24): ?array {
		$cache = $this->cache();
		if ($cache === null) {
			return null;
		}
		$now = intdiv($this->timeFactory->getTime(), 3600);
		$pastKey = self::PREFIX . 'past:' . $hours . ':' . $now;
		$past = $cache->get($pastKey);
		if (!is_array($past) || !is_int($past[0] ?? null) || !is_int($past[1] ?? null) || !is_int($past[2] ?? null)) {
			$past = [0, 0, 0];
			for ($hour = $now - $hours + 1; $hour < $now; $hour++) {
				$past = self::add($past, $cache, $hour);
			}
			$cache->set($pastKey, $past, 3600);
		}
		[$count, $sum, $max] = self::add($past, $cache, $now);
		if ($count === 0) {
			return null;
		}
		return ['samples' => $count, 'averageMicroseconds' => $sum / $count, 'maxMicroseconds' => $max];
	}

	/**
	 * @param array{0: int, 1: int, 2: int} $totals count, sum and maximum
	 * @return array{0: int, 1: int, 2: int}
	 */
	private static function add(array $totals, IMemcache $cache, int $hour): array {
		return [
			$totals[0] + (int)$cache->get(self::PREFIX . $hour . ':n'),
			$totals[1] + (int)$cache->get(self::PREFIX . $hour . ':s'),
			max($totals[2], (int)$cache->get(self::PREFIX . $hour . ':m')),
		];
	}

	private function cache(): ?IMemcache {
		if (!$this->initialised) {
			$this->initialised = true;
			// Counters need atomic increments, which only the memcache types offer.
			$cache = $this->cacheFactory->isAvailable()
				? $this->cacheFactory->createDistributed(Application::APP_ID . '-perf')
				: ($this->cacheFactory->isLocalCacheAvailable() ? $this->cacheFactory->createLocal(Application::APP_ID . '-perf') : null);
			$this->cache = $cache instanceof IMemcache ? $cache : null;
		}
		return $this->cache;
	}
}
