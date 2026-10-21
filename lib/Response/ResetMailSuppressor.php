<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Db\ResetSuppressionMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ICache;
use OCP\ICacheFactory;
use OCP\Security\Events\PasswordResetRequestedEvent;

/**
 * Holds back password reset emails to an account that someone floods with
 * reset requests. The requester gets exactly the same answer either way:
 * core only skips sending ({@see PasswordResetRequestedEvent::preventEmail()}).
 *
 * The check is one primary-key read, cached per account for CACHE_TTL
 * seconds when a memory cache exists.
 */
class ResetMailSuppressor {
	public const CACHE_TTL = 60;

	private ?ICache $cache = null;
	private bool $cacheInitialised = false;

	public function __construct(
		private readonly ResetSuppressionMapper $mapper,
		private readonly ITimeFactory $timeFactory,
		private readonly ICacheFactory $cacheFactory,
	) {
	}

	/**
	 * Hold back reset emails to the account until a time, or extend a
	 * running suppression to then.
	 *
	 * @return int when the suppression ends now
	 */
	public function suppress(string $uid, int $until, ?int $detectionId = null): int {
		$this->mapper->suppress($uid, $detectionId, $this->timeFactory->getTime(), $until);
		$this->cache()?->remove($this->key($uid));
		return $this->suppressedUntil($uid) ?? $until;
	}

	/**
	 * When the suppression of the account's reset emails ends, or null if
	 * they are sent.
	 */
	public function suppressedUntil(string $uid): ?int {
		$now = $this->timeFactory->getTime();
		$cache = $this->cache();
		$cached = $cache?->get($this->key($uid));
		$until = is_int($cached) ? $cached : null;
		if ($until === null) {
			$until = $this->mapper->expiresAt($uid);
			$cache?->set($this->key($uid), $until, self::CACHE_TTL);
		}
		return $until > $now ? $until : null;
	}

	public function isSuppressed(string $uid): bool {
		return $this->suppressedUntil($uid) !== null;
	}

	/**
	 * Prevent the email of this reset request if the account's emails are
	 * held back.
	 *
	 * @return bool whether the email was prevented
	 */
	public function apply(PasswordResetRequestedEvent $event, string $uid): bool {
		if (!$this->isSuppressed($uid)) {
			return false;
		}
		$event->preventEmail();
		return true;
	}

	public function end(string $uid): void {
		$this->mapper->delete($uid);
		$this->cache()?->remove($this->key($uid));
	}

	private function key(string $uid): string {
		return 'rsup:' . hash('sha256', $uid);
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
