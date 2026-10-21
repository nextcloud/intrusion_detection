<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\AppInfo\Application;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;
use OCP\IUserSession;

/**
 * Second-factor providers set up from a session whose login was not
 * confirmed ({@see SessionConfirmation::UNCONFIRMED}). Whoever holds only
 * the password could have set them up, so they never confirm a login that
 * needs extra confirmation. A provider counts again once it is set up anew
 * from a session that is not unconfirmed, and its mark goes when it is
 * removed.
 *
 * Kept in the account's preferences, provider id => when it was set up.
 */
class UntrustedSecondFactors {
	public const USER_KEY = 'untrusted_second_factors';
	/** Marks kept per account; older ones are dropped first */
	public const MAX = 20;

	public function __construct(
		private readonly IUserConfig $userConfig,
		private readonly IUserSession $userSession,
		private readonly SessionConfirmation $confirmation,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * A provider was set up for the account. Only the account's own
	 * session can mark it: an administrator or occ never does.
	 */
	public function registered(string $uid, string $providerId): void {
		if ($this->userSession->getUser()?->getUID() !== $uid) {
			return;
		}
		$marks = $this->marks($uid);
		if ($this->confirmation->isUnconfirmed($uid)) {
			$marks[$providerId] = $this->timeFactory->getTime();
			asort($marks);
			$this->store($uid, array_slice($marks, -self::MAX, null, true));
		} elseif (isset($marks[$providerId])) {
			unset($marks[$providerId]);
			$this->store($uid, $marks);
		}
	}

	public function unregistered(string $uid, string $providerId): void {
		$marks = $this->marks($uid);
		if (isset($marks[$providerId])) {
			unset($marks[$providerId]);
			$this->store($uid, $marks);
		}
	}

	public function isTrusted(string $uid, string $providerId): bool {
		return !isset($this->marks($uid)[$providerId]);
	}

	/**
	 * @return array<string, int>
	 */
	public function marks(string $uid): array {
		$marks = [];
		foreach ($this->userConfig->getValueArray($uid, Application::APP_ID, self::USER_KEY) as $id => $at) {
			if (is_string($id) && is_int($at)) {
				$marks[$id] = $at;
			}
		}
		return $marks;
	}

	/**
	 * @param array<string, int> $marks
	 */
	private function store(string $uid, array $marks): void {
		if ($marks === []) {
			$this->userConfig->deleteUserConfig($uid, Application::APP_ID, self::USER_KEY);
			return;
		}
		$this->userConfig->setValueArray($uid, Application::APP_ID, self::USER_KEY, $marks);
	}
}
