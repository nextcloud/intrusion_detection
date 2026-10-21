<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Db\Lockdown;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Notification\IManager as INotificationManager;

/**
 * Tells every administrator when a lockdown starts and when it ends
 * (concept section 11.14), including the members of the admin group when
 * the notifications go to another group: a lockdown concerns them all.
 *
 * The notification of the start is withdrawn when the lockdown ends, and
 * replaced by the one of the end. Notifications carry the lockdown's id,
 * end, the accounts that started and ended it and the reason given;
 * {@see Notifier} renders them in each reader's language.
 */
class LockdownNotices {
	public const OBJECT_TYPE = 'lockdown';
	public const SUBJECT_STARTED = 'lockdown_started';
	public const SUBJECT_ENDED = 'lockdown_ended';

	public function __construct(
		private readonly AdminRecipients $recipients,
		private readonly INotificationManager $notifications,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return int how many administrators were notified
	 */
	public function started(Lockdown $lockdown): int {
		return $this->send(self::SUBJECT_STARTED, $lockdown);
	}

	/**
	 * @return int how many administrators were notified
	 */
	public function ended(Lockdown $lockdown): int {
		$done = $this->notifications->createNotification();
		$done->setApp(Application::APP_ID)
			->setObject(self::OBJECT_TYPE, (string)$lockdown->getId())
			->setSubject(self::SUBJECT_STARTED);
		$this->notifications->markProcessed($done);
		return $this->send(self::SUBJECT_ENDED, $lockdown);
	}

	private function send(string $subject, Lockdown $lockdown): int {
		$now = $this->timeFactory->getTime();
		$sent = 0;
		foreach ($this->recipients->users(true) as $admin) {
			$notification = $this->notifications->createNotification();
			$notification->setApp(Application::APP_ID)
				->setUser($admin->getUID())
				->setDateTime(new \DateTime('@' . $now))
				->setObject(self::OBJECT_TYPE, (string)$lockdown->getId())
				->setSubject($subject, [
					'lockdown' => $lockdown->getId(),
					'until' => $lockdown->getPlannedEnd(),
					'startedBy' => $lockdown->getStartedBy(),
					'endedBy' => $lockdown->getEndedBy(),
					'reason' => $lockdown->getReason(),
				]);
			$this->notifications->notify($notification);
			$sent++;
		}
		return $sent;
	}
}
