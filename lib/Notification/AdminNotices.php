<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Notification\Db\AlertMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Notification\IManager as INotificationManager;

/**
 * Notices to the administrators about one account, when Nextcloud could not
 * do for that account what a detection asked for:
 *
 * - the account has no email address (or the email failed), so the user
 *   could only be told inside Nextcloud;
 * - the account's password is managed outside Nextcloud, so it must be
 *   reset in that directory instead of being changed here.
 *
 * Each kind is sent at most once per account and hour. Notifications carry
 * only identifiers; {@see Notifier} renders them.
 */
class AdminNotices {
	public const SUBJECT_USER_UNREACHABLE = 'user_unreachable';
	public const SUBJECT_PASSWORD_EXTERNAL = 'password_external';
	public const OBJECT_TYPE = 'account_notice';

	/** Prefixes of the counter keys, short so that "<prefix><uid>" fits the column */
	public const KEY_PREFIXES = [self::SUBJECT_USER_UNREACHABLE => '@unr:', self::SUBJECT_PASSWORD_EXTERNAL => '@pwx:'];

	public const REASON_NO_ADDRESS = 'no_address';
	public const REASON_MAIL_FAILED = 'mail_failed';

	public function __construct(
		private readonly AlertMapper $alerts,
		private readonly AdminRecipients $recipients,
		private readonly INotificationManager $notifications,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @param self::REASON_* $reason
	 * @return int how many administrators were notified
	 */
	public function userUnreachable(string $uid, string $detectionId, string $checkId, string $reason): int {
		return $this->send(self::SUBJECT_USER_UNREACHABLE, $checkId, $uid, [
			'uid' => $uid,
			'detection' => $detectionId,
			'reason' => $reason,
		]);
	}

	/**
	 * @return int how many administrators were notified
	 */
	public function externalPassword(string $uid, ?string $detectionId, string $checkId): int {
		return $this->send(self::SUBJECT_PASSWORD_EXTERNAL, $checkId, $uid, [
			'uid' => $uid,
			'detection' => $detectionId,
		]);
	}

	/**
	 * @param self::SUBJECT_* $subject
	 * @param array<string, scalar|null> $parameters
	 */
	private function send(string $subject, string $checkId, string $uid, array $parameters): int {
		$now = $this->timeFactory->getTime();
		[$alertId, $first] = $this->alerts->hit($checkId, self::KEY_PREFIXES[$subject] . $uid, intdiv($now, 3600), null, $now);
		if (!$first) {
			return 0;
		}
		$sent = 0;
		foreach ($this->recipients->users() as $admin) {
			if ($admin->getUID() === $uid) {
				continue;
			}
			$notification = $this->notifications->createNotification();
			$notification->setApp(Application::APP_ID)
				->setUser($admin->getUID())
				->setDateTime(new \DateTime('@' . $now))
				->setObject(self::OBJECT_TYPE, $alertId)
				->setSubject($subject, $parameters);
			$this->notifications->notify($notification);
			$sent++;
		}
		return $sent;
	}
}
