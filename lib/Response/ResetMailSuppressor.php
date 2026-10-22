<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Db\ResetSuppressionMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Security\Events\PasswordResetRequestedEvent;

/**
 * Holds back password reset emails to an account that someone floods with
 * reset requests. The requester gets exactly the same answer either way:
 * core only skips sending ({@see PasswordResetRequestedEvent::preventEmail()}).
 *
 * Bounded, so that an outsider cannot keep someone from resetting their
 * password: within one PERIOD from its start, a suppression lasts at most
 * MAX_SUPPRESSION in all, however often it is extended; after that, reset
 * emails are sent again until the period is over.
 *
 * The check is one primary-key read, cached per account for CACHE_TTL
 * seconds when a memory cache exists.
 */
class ResetMailSuppressor {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'reset-mail';
	public const CACHE_TTL = 60;
	/** The longest time reset emails to one account are held back within one period */
	public const MAX_SUPPRESSION = 86400;
	/** A suppression and the time in which no new one can start */
	public const PERIOD = 2 * 86400;

	public function __construct(
		private readonly ResetSuppressionMapper $mapper,
		private readonly ITimeFactory $timeFactory,
		private readonly Caches $caches,
	) {
	}

	/**
	 * Hold back reset emails to the account until a time, or extend a
	 * running suppression to then, but never beyond MAX_SUPPRESSION after
	 * the start of the period.
	 *
	 * @return array{until: int, latest: int} when the suppression ends now (in the past once
	 *                                        the period's time is used up), and when at the latest
	 */
	public function suppress(string $uid, int $until, ?int $detectionId = null): array {
		$now = $this->timeFactory->getTime();
		$row = $this->mapper->find($uid);
		if ($row !== null && $row['createdAt'] <= $now - self::PERIOD) {
			$this->mapper->delete($uid);
			$row = null;
		}
		$latest = ($row['createdAt'] ?? $now) + self::MAX_SUPPRESSION;
		if ($now >= $latest) {
			return ['until' => $row['expiresAt'] ?? 0, 'latest' => $latest];
		}
		$this->mapper->suppress($uid, $detectionId, $now, min($until, $latest));
		$this->caches->shared(self::CACHE)?->remove($this->key($uid));
		return ['until' => $this->suppressedUntil($uid) ?? min($until, $latest), 'latest' => $latest];
	}

	/**
	 * Delete suppressions whose period is over, for the cleanup job.
	 */
	public function deleteExpired(): void {
		$now = $this->timeFactory->getTime();
		$this->mapper->deleteExpired($now, $now - self::PERIOD);
	}

	/**
	 * When the suppression of the account's reset emails ends, or null if
	 * they are sent.
	 */
	public function suppressedUntil(string $uid): ?int {
		$now = $this->timeFactory->getTime();
		$cache = $this->caches->shared(self::CACHE);
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
		$this->caches->shared(self::CACHE)?->remove($this->key($uid));
	}

	private function key(string $uid): string {
		return 'rsup:' . hash('sha256', $uid);
	}
}
