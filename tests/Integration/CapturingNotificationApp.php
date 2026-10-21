<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCP\Notification\IApp;
use OCP\Notification\INotification;

/**
 * A notification app for tests: keeps every notification the real manager
 * hands to apps, so tests can see what would have reached the users.
 */
class CapturingNotificationApp implements IApp {
	/** @var list<INotification> */
	public static array $notifications = [];

	#[\Override]
	public function notify(INotification $notification): void {
		self::$notifications[] = $notification;
	}

	#[\Override]
	public function markProcessed(INotification $notification): void {
	}

	#[\Override]
	public function getCount(INotification $notification): int {
		return 0;
	}
}
