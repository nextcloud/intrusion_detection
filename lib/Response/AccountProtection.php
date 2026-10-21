<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Db\ProtectedAccountMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ICache;
use OCP\ICacheFactory;

/**
 * Accounts under extra protection: while an account is protected, every
 * password login to it needs extra confirmation, and non-interactive
 * password logins are refused. App passwords keep working.
 *
 * The protection is read on every successful login, so the answer is cached
 * per account for CACHE_TTL seconds when a memory cache exists. A change made
 * on another web server with only a local cache is seen within that time.
 */
class AccountProtection {
	public const REASON_UNDER_ATTACK = 'under_attack';
	public const CACHE_TTL = 60;

	private ?ICache $cache = null;
	private bool $cacheInitialised = false;

	public function __construct(
		private readonly ProtectedAccountMapper $mapper,
		private readonly ITimeFactory $timeFactory,
		private readonly ICacheFactory $cacheFactory,
		private readonly AuditLogger $audit,
	) {
	}

	/**
	 * Protect an account until a time, or extend its protection to then.
	 *
	 * @return int when the protection ends now
	 */
	public function protect(string $uid, int $until, string $reason = self::REASON_UNDER_ATTACK, ?int $detectionId = null): int {
		$now = $this->timeFactory->getTime();
		$this->mapper->protect($uid, $reason, $detectionId, $now, $until);
		$this->cache()?->remove($this->key($uid));
		return $this->protectedUntil($uid) ?? $until;
	}

	/**
	 * Whether password logins to the account need extra confirmation right
	 * now. One primary-key read, cached.
	 */
	public function isProtected(string $uid): bool {
		return $this->protectedUntil($uid) !== null;
	}

	/**
	 * When the account's protection ends, or null if it is not protected.
	 */
	public function protectedUntil(string $uid): ?int {
		$now = $this->timeFactory->getTime();
		$cache = $this->cache();
		$cached = $cache?->get($this->key($uid));
		if (is_int($cached)) {
			return $cached > $now ? $cached : null;
		}
		$row = $this->mapper->find($uid);
		$until = $row === null ? 0 : $row['expires_at'];
		$cache?->set($this->key($uid), $until, self::CACHE_TTL);
		return $until > $now ? $until : null;
	}

	/**
	 * @return ?array{uid: string, reason: string, detection_id: ?int, created_at: int, expires_at: int} the active protection
	 */
	public function get(string $uid): ?array {
		$row = $this->mapper->find($uid);
		return $row !== null && $row['expires_at'] > $this->timeFactory->getTime() ? $row : null;
	}

	/**
	 * @return list<array{uid: string, reason: string, detection_id: ?int, created_at: int, expires_at: int}>
	 */
	public function active(): array {
		return $this->mapper->findActive($this->timeFactory->getTime());
	}

	/**
	 * End an account's protection early (an administrator's decision).
	 *
	 * @return bool whether the account was protected
	 */
	public function end(string $uid, string $actor): bool {
		$active = $this->get($uid) !== null;
		$this->mapper->delete($uid);
		$this->cache()?->remove($this->key($uid));
		if ($active) {
			$this->audit->log('protection of account %s ended early by %s', ['uid' => $uid, 'actor' => $actor]);
		}
		return $active;
	}

	private function key(string $uid): string {
		return 'prot:' . hash('sha256', $uid);
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
