<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\StaleCredential;

use OCA\IntrusionDetection\AppInfo\Application;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Notification\IManager as INotificationManager;

/**
 * The notifications about a user's stale credentials: the reminder that
 * some exist, which replaces the previous reminder and goes away once the
 * user removed them on their security page, and the notice that some were
 * removed. Both carry only counts and, for removals, at most MAX_NAMES of
 * the names the credentials had.
 */
class StaleCredentialNotices {
	public const SUBJECT_REMINDER = 'stale_credentials';
	public const SUBJECT_REMOVED = 'stale_credentials_removed';
	public const OBJECT_REMINDER = 'stale_credentials';
	public const OBJECT_REMOVED = 'stale_credentials_removed';
	/** At most this many names are kept in a removal notice */
	public const MAX_NAMES = 5;

	public function __construct(
		private readonly INotificationManager $notifications,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	public function remind(string $uid, int $appPasswords, int $sessions): void {
		$this->dismiss($uid);
		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser($uid)
			->setDateTime(new \DateTime('@' . $this->timeFactory->getTime()))
			->setObject(self::OBJECT_REMINDER, $uid)
			->setSubject(self::SUBJECT_REMINDER, ['appPasswords' => $appPasswords, 'sessions' => $sessions, 'days' => StaleCredentials::DAYS]);
		$this->notifications->notify($notification);
	}

	/**
	 * @param list<array{name: string, kind: string}> $removed
	 */
	public function removed(string $uid, array $removed, int $days): void {
		if ($removed === []) {
			return;
		}
		$now = $this->timeFactory->getTime();
		$appPasswords = count(array_filter($removed, static fn (array $r): bool => $r['kind'] === StaleCredentials::KIND_APP_PASSWORD));
		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser($uid)
			->setDateTime(new \DateTime('@' . $now))
			->setObject(self::OBJECT_REMOVED, (string)$now)
			->setSubject(self::SUBJECT_REMOVED, [
				'appPasswords' => $appPasswords,
				'sessions' => count($removed) - $appPasswords,
				'days' => $days,
				'names' => array_slice(array_values(array_unique(array_column($removed, 'name'))), 0, self::MAX_NAMES),
			]);
		$this->notifications->notify($notification);
	}

	/**
	 * Take the reminder back, for example once the user removed what it was about.
	 */
	public function dismiss(string $uid): void {
		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser($uid)
			->setObject(self::OBJECT_REMINDER, $uid);
		$this->notifications->markProcessed($notification);
	}
}
