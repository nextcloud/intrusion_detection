<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\UserKeys;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;

/**
 * The user value that says an account must choose a new password at its
 * next login: the time it was required, or 0. It is not lazy, so reading it
 * comes with the account's other settings that core loads at login.
 */
class PasswordChangeFlag {

	public function __construct(
		private readonly IUserConfig $userConfig,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	public function isRequired(string $uid): bool {
		return $this->requiredSince($uid) !== null;
	}

	/**
	 * When the new password was required, or null if it is not.
	 */
	public function requiredSince(string $uid): ?int {
		$since = $this->userConfig->getValueInt($uid, Application::APP_ID, UserKeys::FORCE_PASSWORD_CHANGE);
		return $since > 0 ? $since : null;
	}

	/**
	 * @return int when it was required (an earlier requirement is kept)
	 */
	public function set(string $uid): int {
		$since = $this->requiredSince($uid);
		if ($since !== null) {
			return $since;
		}
		$now = $this->timeFactory->getTime();
		$this->userConfig->setValueInt($uid, Application::APP_ID, UserKeys::FORCE_PASSWORD_CHANGE, $now);
		return $now;
	}

	/**
	 * @return bool whether it was set
	 */
	public function clear(string $uid): bool {
		if (!$this->isRequired($uid)) {
			return false;
		}
		$this->userConfig->deleteUserConfig($uid, Application::APP_ID, UserKeys::FORCE_PASSWORD_CHANGE);
		return true;
	}
}
