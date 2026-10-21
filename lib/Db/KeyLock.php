<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCA\IntrusionDetection\AppInfo\Application;
use OCP\ICacheFactory;
use OCP\IMemcache;

/**
 * Runs a check-and-write under a lock per key, so parallel requests do not
 * both insert what each found missing.
 *
 * - The lock is an atomic add in the memory cache (distributed if there is
 *   one), never a database row: core's database locking costs several
 *   writes per lock.
 * - A lock ends after TTL seconds, so one left by a request that died
 *   stops mattering soon.
 * - A held lock is waited for once (PAUSE_US). When it is still held, or
 *   without a memory cache, the work runs unlocked: a duplicate row or a
 *   lost hit count is harmless, a lost block or detection is not.
 */
class KeyLock {
	public const TTL = 5;
	public const PAUSE_US = 25000;
	public const PREFIX = Application::APP_ID . '-lock';

	private IMemcache|null|false $cache = false;

	public function __construct(
		private readonly ICacheFactory $cacheFactory,
	) {
	}

	/**
	 * @template T
	 * @param string $scope what the keys are, e.g. "ban"
	 * @param \Closure(): T $work
	 * @return T
	 */
	public function run(string $scope, string $key, \Closure $work): mixed {
		$cache = $this->cache();
		if ($cache === null) {
			return $work();
		}
		$lock = $scope . '/' . md5($key);
		$held = $cache->add($lock, 1, self::TTL);
		if (!$held) {
			usleep(self::PAUSE_US);
			$held = $cache->add($lock, 1, self::TTL);
		}
		try {
			return $work();
		} finally {
			if ($held) {
				$cache->remove($lock);
			}
		}
	}

	private function cache(): ?IMemcache {
		if ($this->cache === false) {
			$cache = $this->cacheFactory->isAvailable()
				? $this->cacheFactory->createDistributed(self::PREFIX)
				: ($this->cacheFactory->isLocalCacheAvailable() ? $this->cacheFactory->createLocal(self::PREFIX) : null);
			// add() is atomic only on the memcache types.
			$this->cache = $cache instanceof IMemcache ? $cache : null;
		}
		return $this->cache;
	}
}
