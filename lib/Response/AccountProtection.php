<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Response\Db\ProtectedAccountMapper;
use OCP\AppFramework\Utility\ITimeFactory;

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
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'protected-accounts';
	public const REASON_UNDER_ATTACK = 'under_attack';
	public const CACHE_TTL = 60;

	public function __construct(
		private readonly ProtectedAccountMapper $mapper,
		private readonly ITimeFactory $timeFactory,
		private readonly Caches $caches,
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
		$this->caches->shared(self::CACHE)?->remove($this->key($uid));
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
		$cache = $this->caches->shared(self::CACHE);
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
	public function active(int $limit = 200): array {
		return $this->mapper->findActive($this->timeFactory->getTime(), $limit);
	}

	/**
	 * End an account's protection early (an administrator's decision).
	 *
	 * @return bool whether the account was protected
	 */
	public function end(string $uid, string $actor): bool {
		$active = $this->get($uid) !== null;
		$this->mapper->delete($uid);
		$this->caches->shared(self::CACHE)?->remove($this->key($uid));
		if ($active) {
			$this->audit->log('protection of account %s ended early by %s', ['uid' => $uid, 'actor' => $actor]);
		}
		return $active;
	}

	private function key(string $uid): string {
		return 'prot:' . hash('sha256', $uid);
	}
}
