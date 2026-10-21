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
 * Second-factor providers set up from a session whose login proved no
 * more than the password. Whoever holds only the password could have set
 * them up, so for a while they never confirm a login that needs extra
 * confirmation:
 *
 * - set up from a session whose login was not confirmed
 *   ({@see SessionConfirmation::UNCONFIRMED}): until it is set up anew from
 *   a session that is not unconfirmed;
 * - set up from a session whose login needed no confirmation
 *   ({@see SessionConfirmation::PASSWORD}): for PASSWORD_DELAY, so that the
 *   account holder has time to notice the change;
 * - set up from a session whose login proved more
 *   ({@see SessionConfirmation::PROVEN}): at once, and an earlier mark goes.
 *
 * A mark also goes when the provider is removed. Kept in the account's
 * preferences, provider id => when it was set up, or for a mark that ends
 * by itself, provider id => ['at' => when it was set up, 'until' => when it counts].
 */
class UntrustedSecondFactors {
	public const USER_KEY = 'untrusted_second_factors';
	/** Marks kept per account; older ones are dropped first */
	public const MAX = 20;
	/** How long a provider set up from a session that proved only the password does not count */
	public const PASSWORD_DELAY = 7 * 86400;

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
		$marks = $this->stored($uid);
		$now = $this->timeFactory->getTime();
		$mark = match ($this->confirmation->level($uid)) {
			SessionConfirmation::UNCONFIRMED => $now,
			SessionConfirmation::PASSWORD => ['at' => $now, 'until' => $now + self::PASSWORD_DELAY],
			default => null,
		};
		if ($mark === null) {
			if (isset($marks[$providerId])) {
				unset($marks[$providerId]);
				$this->store($uid, $marks);
			}
			return;
		}
		unset($marks[$providerId]);
		$marks[$providerId] = $mark;
		$this->store($uid, array_slice($marks, -self::MAX, null, true));
	}

	public function unregistered(string $uid, string $providerId): void {
		$marks = $this->stored($uid);
		if (isset($marks[$providerId])) {
			unset($marks[$providerId]);
			$this->store($uid, $marks);
		}
	}

	public function isTrusted(string $uid, string $providerId): bool {
		return !isset($this->marks($uid)[$providerId]);
	}

	/**
	 * The providers that do not count now.
	 *
	 * @return array<string, int> provider id => when it was set up
	 */
	public function marks(string $uid): array {
		return array_map(static fn (int|array $mark): int => is_int($mark) ? $mark : $mark['at'], $this->stored($uid));
	}

	/**
	 * The stored marks, oldest first, without the ones that ended by themselves.
	 *
	 * @return array<string, int|array{at: int, until: int}>
	 */
	private function stored(string $uid): array {
		$now = $this->timeFactory->getTime();
		$marks = [];
		foreach ($this->userConfig->getValueArray($uid, Application::APP_ID, self::USER_KEY) as $id => $mark) {
			if (!is_string($id)) {
				continue;
			}
			if (is_int($mark)) {
				$marks[$id] = $mark;
			} elseif (is_array($mark) && is_int($mark['at'] ?? null) && is_int($mark['until'] ?? null) && $mark['until'] > $now) {
				$marks[$id] = ['at' => $mark['at'], 'until' => $mark['until']];
			}
		}
		uasort($marks, static fn (int|array $a, int|array $b): int => (is_int($a) ? $a : $a['at']) <=> (is_int($b) ? $b : $b['at']));
		return $marks;
	}

	/**
	 * @param array<string, int|array{at: int, until: int}> $marks
	 */
	private function store(string $uid, array $marks): void {
		if ($marks === []) {
			$this->userConfig->deleteUserConfig($uid, Application::APP_ID, self::USER_KEY);
			return;
		}
		$this->userConfig->setValueArray($uid, Application::APP_ID, self::USER_KEY, $marks);
	}
}
