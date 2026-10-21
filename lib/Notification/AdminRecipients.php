<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCP\IGroupManager;
use OCP\IUser;

/**
 * Who "the administrators" are for notifications: the enabled members of the
 * groups in the setting `notify_admin_group` (by default the admin group).
 * Alerts about administration changes also always reach the admin group, so
 * changing that setting cannot silence them.
 */
class AdminRecipients {
	/** At most this many people are notified, so a huge group cannot turn one alert into a flood */
	public const MAX = 100;
	public const ADMIN_GROUP = 'admin';

	public function __construct(
		private readonly Settings $settings,
		private readonly IGroupManager $groupManager,
	) {
	}

	/**
	 * @return list<IUser>
	 */
	public function users(bool $withAdminGroup = false): array {
		$users = [];
		$groups = $this->settings->global(GlobalSettings::NOTIFY_ADMIN_GROUP);
		$groups = is_array($groups) ? $groups : [];
		if ($withAdminGroup && !in_array(self::ADMIN_GROUP, $groups, true)) {
			$groups[] = self::ADMIN_GROUP;
		}
		foreach ($groups as $groupId) {
			$group = $this->groupManager->get($groupId);
			if ($group === null) {
				continue;
			}
			foreach ($group->searchUsers('', self::MAX) as $user) {
				if ($user->isEnabled()) {
					$users[$user->getUID()] = $user;
				}
				if (count($users) >= self::MAX) {
					break 2;
				}
			}
		}
		return array_values($users);
	}
}
