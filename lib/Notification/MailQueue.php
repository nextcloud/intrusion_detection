<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\BackgroundJob\AlertMailJob;
use OCA\IntrusionDetection\Notification\Db\AlertMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJobList;
use Psr\Log\LoggerInterface;

/**
 * Queues the emails about detections for {@see AlertMailJob}, so that the
 * request that caused a detection, often an attacker's, never waits for
 * the mail server.
 *
 * A job's argument holds only the kind of email, the detection id and the
 * recipient's account: the job builds the email from the stored detection,
 * in the recipient's language and time zone, when it runs. Emails a user
 * waits for at that moment (login codes, lock links) are not queued.
 *
 * Emails to users and share owners are capped across all accounts at
 * MAX_USER_MAILS_PER_HOUR, so that an attack on many accounts cannot make
 * the server send one email per account. Above the cap, people are told
 * inside Nextcloud only, and the log says once per hour that the cap was
 * reached. Emails to administrators are not capped here: {@see AdminAlerts}
 * sends at most one per check and hour.
 */
class MailQueue {
	public const KIND_USER = 'user';
	public const KIND_ADMIN = 'admin';
	public const KIND_SHARE_OWNER = 'share_owner';

	/** Emails to users and share owners, per hour across all accounts */
	public const MAX_USER_MAILS_PER_HOUR = 100;
	/** Counter of the hour's emails to users and share owners */
	public const CAP_CHECK = '@mail_queue';
	public const CAP_KEY = 'users';

	public function __construct(
		private readonly IJobList $jobList,
		private readonly AlertMapper $alerts,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * Queue the email about a detection to its account.
	 *
	 * @return bool false when the hour's cap is reached and nothing was queued
	 */
	public function user(int $detectionId, string $uid): bool {
		return $this->underCap() && $this->add(self::KIND_USER, $detectionId, $uid);
	}

	/**
	 * Queue the email about a detection to the people who manage its share.
	 *
	 * @return bool false when the hour's cap is reached and nothing was queued
	 */
	public function shareOwners(int $detectionId): bool {
		return $this->underCap() && $this->add(self::KIND_SHARE_OWNER, $detectionId, null);
	}

	/**
	 * Queue the alert email about a detection to the administrators.
	 */
	public function admins(int $detectionId): void {
		$this->add(self::KIND_ADMIN, $detectionId, null);
	}

	/**
	 * @param self::KIND_* $kind
	 */
	private function add(string $kind, int $detectionId, ?string $uid): bool {
		$argument = ['kind' => $kind, 'detection' => $detectionId];
		if ($uid !== null) {
			$argument['uid'] = $uid;
		}
		$this->jobList->add(AlertMailJob::class, $argument);
		return true;
	}

	/**
	 * Count one email to a user against the hour's cap.
	 */
	private function underCap(): bool {
		$now = $this->timeFactory->getTime();
		[$id] = $this->alerts->hit(self::CAP_CHECK, self::CAP_KEY, intdiv($now, 3600), null, $now);
		$hits = $this->alerts->find($id)['hits'] ?? PHP_INT_MAX;
		if ($hits <= self::MAX_USER_MAILS_PER_HOUR) {
			return true;
		}
		if ($hits === self::MAX_USER_MAILS_PER_HOUR + 1) {
			$this->logger->warning('Intrusion detection queued {max} emails to users within the hour; until the hour ends, users are told inside Nextcloud only', [
				'max' => self::MAX_USER_MAILS_PER_HOUR,
			]);
		}
		return false;
	}
}
