<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\AdminChange\Approvers;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\IL10N;
use OCP\IUser;
use OCP\SetupCheck\ISetupCheck;
use OCP\SetupCheck\SetupResult;

/**
 * Setup check 10: administrators need an email address, so alerts reach them
 * outside Nextcloud, and a second factor, so a stolen password alone does
 * not give an intruder the server.
 *
 * - error: no administrator has an email address or a second factor;
 * - warning: some administrators lack one of them, or none has an email address;
 * - success otherwise.
 */
class AdminContactCheck implements ISetupCheck {
	/** Backup codes alone are not a second factor */
	private const BACKUP_CODES = 'backup_codes';
	/** At most this many names are listed */
	private const MAX_NAMES = 10;

	public function __construct(
		private readonly Approvers $approvers,
		private readonly IRegistry $twoFactor,
		private readonly IL10N $l,
	) {
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Email and second factor of administrators');
	}

	#[\Override]
	public function getCategory(): string {
		return 'security';
	}

	#[\Override]
	public function run(): SetupResult {
		$admins = $this->approvers->all();
		if ($admins === []) {
			return SetupResult::success($this->l->t('The admin group has no enabled members.'));
		}
		$withoutEmail = [];
		$withoutSecondFactor = [];
		foreach ($admins as $admin) {
			if ((string)$admin->getEMailAddress() === '') {
				$withoutEmail[] = $admin->getUID();
			}
			if (!$this->hasSecondFactor($admin)) {
				$withoutSecondFactor[] = $admin->getUID();
			}
		}

		if (count($withoutEmail) === count($admins) && count($withoutSecondFactor) === count($admins)) {
			return SetupResult::error($this->l->t('No administrator has an email address or a second factor. Security alerts can only be seen inside Nextcloud, where an intruder in an administrator account sees them too, and a stolen password is enough to take over the server. Add an email address and set up a second factor for every administrator.'));
		}
		if ($withoutEmail === [] && $withoutSecondFactor === []) {
			return SetupResult::success($this->l->t('Every administrator has an email address and a second factor.'));
		}

		$problems = [];
		if (count($withoutEmail) === count($admins)) {
			$problems[] = $this->l->t('No administrator has an email address, so security alerts can only be seen inside Nextcloud, where an intruder in an administrator account sees them too.');
		} elseif ($withoutEmail !== []) {
			$problems[] = $this->l->n(
				'%n administrator has no email address and gets security alerts only inside Nextcloud: %s.',
				'%n administrators have no email address and get security alerts only inside Nextcloud: %s.',
				count($withoutEmail),
				[$this->names($withoutEmail)],
			);
		}
		if ($withoutSecondFactor !== []) {
			$problems[] = $this->l->n(
				'%n administrator has no second factor, so the password alone opens the account: %s.',
				'%n administrators have no second factor, so the password alone opens their accounts: %s.',
				count($withoutSecondFactor),
				[$this->names($withoutSecondFactor)],
			);
		}
		return SetupResult::warning(implode(' ', $problems));
	}

	private function hasSecondFactor(IUser $user): bool {
		foreach ($this->twoFactor->getProviderStates($user) as $provider => $enabled) {
			if ($enabled && $provider !== self::BACKUP_CODES) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param list<string> $uids
	 */
	private function names(array $uids): string {
		$shown = array_slice($uids, 0, self::MAX_NAMES);
		$text = implode(', ', $shown);
		return count($uids) > count($shown) ? $this->l->t('%1$s and %2$s more', [$text, (string)(count($uids) - count($shown))]) : $text;
	}
}
