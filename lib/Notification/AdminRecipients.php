<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCP\ICache;
use OCP\ICacheFactory;
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
	/** That no recipient has an email address is remembered this long */
	public const REMEMBER_WITHOUT_EMAIL = 60;

	private ?ICache $cache = null;
	private bool $cacheInitialised = false;

	public function __construct(
		private readonly Settings $settings,
		private readonly IGroupManager $groupManager,
		private readonly ICacheFactory $cacheFactory,
	) {
	}

	/**
	 * Whether none of the recipients had an email address when last looked
	 * at, within REMEMBER_WITHOUT_EMAIL seconds: then an alert email need not
	 * look the group members up again. Always false without a memory cache.
	 */
	public function knownWithoutEmail(bool $withAdminGroup = false): bool {
		return $this->cache()?->get($this->withoutEmailKey($withAdminGroup)) !== null;
	}

	public function rememberWithoutEmail(bool $withAdminGroup = false): void {
		$this->cache()?->set($this->withoutEmailKey($withAdminGroup), 1, self::REMEMBER_WITHOUT_EMAIL);
	}

	/**
	 * @return list<IUser>
	 */
	public function users(bool $withAdminGroup = false): array {
		$users = [];
		foreach ($this->groups($withAdminGroup) as $groupId) {
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

	/**
	 * @return list<string>
	 */
	private function groups(bool $withAdminGroup): array {
		$groups = $this->settings->global(GlobalSettings::NOTIFY_ADMIN_GROUP);
		$groups = is_array($groups) ? array_map('strval', $groups) : [];
		if ($withAdminGroup && !in_array(self::ADMIN_GROUP, $groups, true)) {
			$groups[] = self::ADMIN_GROUP;
		}
		return $groups;
	}

	private function withoutEmailKey(bool $withAdminGroup): string {
		return 'recipients:no-email:' . md5(implode("\0", $this->groups($withAdminGroup)));
	}

	private function cache(): ?ICache {
		if (!$this->cacheInitialised) {
			$this->cacheInitialised = true;
			$this->cache = $this->cacheFactory->isLocalCacheAvailable() ? $this->cacheFactory->createLocal(Application::APP_ID) : null;
		}
		return $this->cache;
	}
}
