<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCP\Lock\ILockingProvider;
use OCP\Lock\LockedException;

/**
 * Runs a check-and-write under a lock per key, so parallel requests do not
 * both insert what each found missing. When the lock cannot be had in time
 * (a stuck request), the work runs anyway: a duplicate row is harmless, a
 * lost block or detection is not.
 */
class KeyLock {
	private const TRIES = 20;
	private const PAUSE_US = 25000;

	public function __construct(
		private readonly ILockingProvider $locks,
	) {
	}

	/**
	 * @template T
	 * @param string $scope what the keys are, e.g. "ban"
	 * @param \Closure(): T $work
	 * @return T
	 */
	public function run(string $scope, string $key, \Closure $work): mixed {
		$lock = 'intrusion_detection/' . $scope . '/' . md5($key);
		$held = false;
		for ($try = 0; $try < self::TRIES && !$held; $try++) {
			try {
				$this->locks->acquireLock($lock, ILockingProvider::LOCK_EXCLUSIVE);
				$held = true;
			} catch (LockedException) {
				usleep(self::PAUSE_US);
			}
		}
		try {
			return $work();
		} finally {
			if ($held) {
				$this->locks->releaseLock($lock, ILockingProvider::LOCK_EXCLUSIVE);
			}
		}
	}
}
