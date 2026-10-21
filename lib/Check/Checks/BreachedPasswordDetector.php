<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Breach\PwnedPasswordsClient;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;
use OCP\IUser;

/**
 * Checks a password against the breach list at an interactive login
 * (concept section 10.5), and keeps the result per account:
 *
 * - `breach_checked_at`: when the current password was last checked;
 * - `breached`: set while the current password is known to be on the list.
 *
 * The password is checked when it was never checked, or longer ago than
 * `recheck_days`. A password change clears both values, so the new password
 * is checked at the next login. When the service cannot be reached, nothing
 * is stored and the next login tries again.
 *
 * The detection never holds the password, its hash, the prefix sent or the
 * count in the list (a count can identify a password).
 */
class BreachedPasswordDetector {
	public const KEY_CHECKED_AT = 'breach_checked_at';
	public const KEY_BREACHED = 'breached';

	/** @var array<string, ?bool> results of this request, per account */
	private array $results = [];

	public function __construct(
		private readonly Settings $settings,
		private readonly PwnedPasswordsClient $client,
		private readonly IUserConfig $userConfig,
		private readonly ResponseEngine $engine,
		private readonly RemoteAddressResolver $addresses,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * Whether the account's current password was found on the list. Reads
	 * one stored value; contacts nothing. This is the stored state, whatever
	 * the check's mode is now.
	 */
	public function isBreached(IUser|string $user): bool {
		return $this->userConfig->getValueBool(self::uid($user), Application::APP_ID, self::KEY_BREACHED, false, true);
	}

	/**
	 * When the account's current password was last checked, or null.
	 */
	public function checkedAt(IUser|string $user): ?int {
		$checkedAt = $this->userConfig->getValueInt(self::uid($user), Application::APP_ID, self::KEY_CHECKED_AT, 0, true);
		return $checkedAt > 0 ? $checkedAt : null;
	}

	public function isDue(IUser|string $user): bool {
		$checkedAt = $this->checkedAt($user);
		$recheck = $this->settings->paramInt(BreachedPassword::ID, 'recheck_days') * 86400;
		return $checkedAt === null || $checkedAt <= $this->timeFactory->getTime() - $recheck;
	}

	/**
	 * Check the password of an interactive login, if the check runs and the
	 * account is due, and answer a detection with the configured responses.
	 *
	 * The caller must only pass the password of an interactive password
	 * login ({@see \OCA\IntrusionDetection\Login\InteractiveLogin}). Within
	 * one request the account is checked once; later calls return the same
	 * result.
	 *
	 * @return ?bool true when the password is on the list, false when it is
	 *               not, null when it was not checked now (check off, not due,
	 *               allowlisted address, service unreachable)
	 */
	public function checkAtLogin(IUser $user, #[\SensitiveParameter] string $password, ?string $userAgent = null): ?bool {
		$uid = $user->getUID();
		if (array_key_exists($uid, $this->results)) {
			return $this->results[$uid];
		}
		$this->results[$uid] = null;

		if ($password === '' || !$this->settings->modeState(BreachedPassword::ID)->runs()) {
			return null;
		}
		$source = $this->addresses->current();
		if ($source !== null && $this->addresses->isBypassListed($source)) {
			return null;
		}
		if (!$this->isDue($uid)) {
			return null;
		}

		$count = $this->client->count($password);
		if ($count === null) {
			return null;
		}
		$found = $count >= $this->settings->paramInt(BreachedPassword::ID, 'min_count');
		$this->userConfig->setValueInt($uid, Application::APP_ID, self::KEY_CHECKED_AT, $this->timeFactory->getTime(), true);
		if ($found) {
			$this->userConfig->setValueBool($uid, Application::APP_ID, self::KEY_BREACHED, true, true);
		} else {
			$this->userConfig->deleteUserConfig($uid, Application::APP_ID, self::KEY_BREACHED);
		}
		$this->results[$uid] = $found;

		if ($found) {
			$this->engine->handle(new DetectionDraft(
				checkId: BreachedPassword::ID,
				source: $source,
				uid: $uid,
				facts: ['trigger' => 'login'],
				merge: DetectionDraft::MERGE_USER,
				mergeWindow: 86400,
				userAgent: $userAgent,
			));
		}
		return $found;
	}

	/**
	 * Forget the result for the account, so its password is checked at the
	 * next interactive login: after a password change, or by an admin.
	 */
	public function reset(IUser|string $user): void {
		$uid = self::uid($user);
		$this->userConfig->deleteUserConfig($uid, Application::APP_ID, self::KEY_CHECKED_AT);
		$this->userConfig->deleteUserConfig($uid, Application::APP_ID, self::KEY_BREACHED);
		unset($this->results[$uid]);
	}

	private static function uid(IUser|string $user): string {
		return $user instanceof IUser ? $user->getUID() : $user;
	}
}
