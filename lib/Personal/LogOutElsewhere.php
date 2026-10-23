<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Personal;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Response\Tokens;
use OCP\IUser;

/**
 * "Log out everywhere else" on the user's security page (concept sections
 * 11.5.1 and 15.1): every other browser session of the account ends, and
 * every remembered browser except this one is forgotten, so that their next
 * login is confirmed again where needed.
 *
 * App passwords and connected devices keep working; core's device list
 * revokes those. Only a browser session can do this, never a request made
 * with an app password.
 */
class LogOutElsewhere {
	public function __construct(
		private readonly Tokens $tokens,
		private readonly CoreSession $coreSession,
		private readonly KnownDevices $knownDevices,
		private readonly AuditLogger $audit,
	) {
	}

	/**
	 * @return ?array{sessions: int, devices: int} what was ended, or null when the request is not a browser session of the user
	 */
	public function run(IUser $user): ?array {
		$uid = $user->getUID();
		$current = $this->coreSession->tokenId();
		if ($current === null || $this->coreSession->usesAppPassword() || !$this->tokens->isSession($uid, $current)) {
			return null;
		}
		$sessions = $this->tokens->invalidateSessionsExcept($uid, $current);
		$devices = $this->knownDevices->forgetAll($uid, 'the user logged out everywhere else', keepCurrent: true);
		$this->audit->log('%s logged out everywhere else: %s other sessions ended, %s remembered devices forgotten', [
			'uid' => $uid,
			'sessions' => (string)$sessions,
			'devices' => (string)$devices,
		]);
		return ['sessions' => $sessions, 'devices' => $devices];
	}
}
