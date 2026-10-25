<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\LoginHistory;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;

/**
 * Reads an account's logins together with what its own history says about
 * them ({@see SignInHabits}): one query of the login history, which also
 * reads up to HABIT_LOGINS rows of the habit window before the logins
 * asked for, and one of the trusted networks.
 */
class SignInHistory {
	/** Logins before the asked ones read at most, to label them */
	public const HABIT_LOGINS = 500;

	public function __construct(
		private readonly LoginHistory $loginHistory,
		private readonly TrustedNetworks $trustedNetworks,
		private readonly UserMessages $messages,
		private readonly AppSettings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * The account's logins since a time, newest first, and its habits. A
	 * login whose habit window reaches back past the login history's
	 * retention, or past the rows read, is labelled only where nothing new
	 * is claimed.
	 *
	 * @param int $limit the most logins returned
	 * @return array{0: list<LoginHistoryEntry>, 1: SignInHabits}
	 */
	public function read(IUser $user, int $since, int $limit): array {
		$uid = $user->getUID();
		$from = $since - SignInHabits::WINDOW;
		$cap = $limit + self::HABIT_LOGINS;
		$read = $this->loginHistory->forUser($uid, $from, null, $cap);
		$complete = max(
			count($read) < $cap ? $from : end($read)->createdAt + 1,
			$this->timeFactory->getTime() - $this->settings->retentionDays() * 86400,
		);
		$shown = array_slice(array_values(array_filter($read, static fn (LoginHistoryEntry $e): bool => $e->createdAt >= $since)), 0, $limit);
		$trusted = array_column($this->trustedNetworks->forUser($uid), 'network');
		return [$shown, new SignInHabits($read, $trusted, $this->messages->timeZoneOf($user), $complete)];
	}
}
