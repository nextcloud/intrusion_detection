<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Notification\AdminRecipients;
use OCA\IntrusionDetection\Notification\MailReach;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\IL10N;
use OCP\IUser;

/**
 * The Notifications tab: who gets the administrator notifications, whether
 * email works, and which checks notify administrators or users.
 *
 * @psalm-import-type IntrusionDetectionNotifications from ResponseDefinitions
 */
class NotificationOverview {
	public function __construct(
		private readonly AdminRecipients $recipients,
		private readonly Prerequisites $prerequisites,
		private readonly MailReach $reach,
		private readonly CheckRegistry $registry,
		private readonly CheckSettings $settings,
	) {
	}

	/**
	 * @return IntrusionDetectionNotifications
	 */
	public function get(?IUser $me, IL10N $l): array {
		$recipients = $this->recipients->users();
		$checks = [];
		foreach ($this->registry->configurable() as $check) {
			$selected = $this->settings->responses($check->id);
			$checks[] = [
				'id' => $check->id,
				'name' => $check->texts($l)->name,
				'category' => $check->category->value,
				'mode' => $this->settings->modeState($check->id)->effective->value,
				'admin' => in_array(ResponseType::NotifyAdmin, $selected, true),
				'user' => in_array(ResponseType::NotifyUser, $selected, true),
				'adminAvailable' => $check->allowsResponse(ResponseType::NotifyAdmin),
				'userAvailable' => $check->allowsResponse(ResponseType::NotifyUser),
			];
		}
		$myEmail = (string)$me?->getEMailAddress();
		return [
			'recipients' => array_map(fn (IUser $u): array => [
				'uid' => $u->getUID(),
				'displayName' => $u->getDisplayName(),
				'hasEmail' => $this->reach->hasAddress($u),
			], $recipients),
			'recipientLimit' => AdminRecipients::MAX,
			'mail' => $this->prerequisites->hasMail(),
			'me' => [
				'uid' => $me?->getUID() ?? '',
				'email' => $myEmail === '' ? null : $myEmail,
				'recipient' => $me !== null && array_filter($recipients, static fn (IUser $u): bool => $u->getUID() === $me->getUID()) !== [],
			],
			'checks' => $checks,
		];
	}
}
