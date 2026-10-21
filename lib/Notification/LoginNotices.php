<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Db\KnownDeviceMapper;
use OCA\IntrusionDetection\KnownDevice\KnownDevice;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;

/**
 * The security notice at the next login, for users Nextcloud could only
 * tell inside Nextcloud (no email address, or the email failed; concept
 * section 11.1, item 3). A notification alone is weak: an attacker logged
 * in as the user sees it too and can dismiss it.
 *
 * - {@see UserAlerts} remembers when the first such event happened (a user
 *   value, read with the account's other values at login).
 * - The next interactive login from one of the user's known devices, which
 *   an attacker with the password does not have, shows the events since
 *   then once, with the "Was this you?" answers, before the start page. A
 *   user without any known device sees it at their next interactive login.
 * - Continuing clears it.
 */
class LoginNotices {
	public const USER_KEY = 'login_notice_since';

	public function __construct(
		private readonly IUserConfig $userConfig,
		private readonly SessionState $state,
		private readonly KnownDeviceMapper $devices,
		private readonly KnownDevices $knownDevices,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * An event the user could only be told about inside Nextcloud. The
	 * earliest one that was not shown yet is kept.
	 */
	public function remember(string $uid, int $at): void {
		$since = $this->since($uid);
		if ($since === null || $at < $since) {
			$this->userConfig->setValueInt($uid, Application::APP_ID, self::USER_KEY, $at);
		}
	}

	/**
	 * When the oldest event not shown yet happened, or null.
	 */
	public function since(string $uid): ?int {
		$since = $this->userConfig->getValueInt($uid, Application::APP_ID, self::USER_KEY);
		return $since > 0 ? $since : null;
	}

	/**
	 * An interactive login: show the notice in this session if it is due
	 * and the login comes from a known device, or the user has none.
	 */
	public function atLogin(string $uid, ?KnownDevice $device): void {
		$since = $this->since($uid);
		if ($since === null) {
			return;
		}
		$now = $this->timeFactory->getTime();
		if ($device === null && $this->devices->forUser($uid, $now - $this->knownDevices->duration(), 1) !== []) {
			return;
		}
		$this->state->set(SessionState::LOGIN_NOTICE, ['uid' => $uid, 'since' => $since]);
	}

	/**
	 * Since when the events of the current session's notice are shown, or
	 * null when the session has no notice for the account.
	 */
	public function shownSince(string $uid): ?int {
		$marker = $this->state->get(SessionState::LOGIN_NOTICE);
		return $marker !== null && ($marker['uid'] ?? null) === $uid && is_int($marker['since'] ?? null) ? $marker['since'] : null;
	}

	/**
	 * The user saw the notice and continued.
	 */
	public function done(string $uid): void {
		$this->state->remove(SessionState::LOGIN_NOTICE);
		$this->userConfig->deleteUserConfig($uid, Application::APP_ID, self::USER_KEY);
	}
}
