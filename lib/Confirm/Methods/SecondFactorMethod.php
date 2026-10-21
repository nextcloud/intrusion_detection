<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm\Methods;

use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCP\Authentication\TwoFactorAuth\IChallengeRequester;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\IUser;

/**
 * The account's second factor. At a login through the login form, core's
 * own challenge right after the password is the confirmation, so nothing
 * else is asked. In a running session it is asked again through
 * {@see IChallengeRequester}.
 *
 * Only a second factor that is set up counts: an account for which two
 * factors are enforced but that has no provider yet would set one up with
 * just the password, which proves nothing.
 */
class SecondFactorMethod implements IConfirmationMethod {
	/** Backup codes alone do not make an account use two factors, as in core */
	private const BACKUP_CODES = 'backup_codes';

	public function __construct(
		private readonly IChallengeRequester $challenges,
		private readonly IRegistry $registry,
	) {
	}

	#[\Override]
	public function id(): string {
		return self::SECOND_FACTOR;
	}

	#[\Override]
	public function isAvailable(IUser $user, StepUpPolicy $policy): bool {
		if (!$this->challenges->isAvailable($user)) {
			return false;
		}
		foreach ($this->registry->getProviderStates($user) as $providerId => $enabled) {
			if ($enabled && $providerId !== self::BACKUP_CODES) {
				return true;
			}
		}
		return false;
	}

	#[\Override]
	public function begin(IUser $user, StepUpState $state): string {
		return self::CONFIRMED;
	}

	/**
	 * Ask the current session for the second factor again.
	 *
	 * @return string the URL of core's challenge
	 * @throws \LogicException when the session cannot be challenged
	 */
	public function requestChallenge(IUser $user, string $redirectUrl): string {
		return $this->challenges->requestChallenge($user, $redirectUrl);
	}
}
