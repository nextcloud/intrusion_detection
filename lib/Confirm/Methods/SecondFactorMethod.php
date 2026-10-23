<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm\Methods;

use OCA\IntrusionDetection\Confirm\AccountMethods;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Confirm\UntrustedSecondFactors;
use OCP\Authentication\TwoFactorAuth\IChallengeRequester;
use OCP\IUser;

/**
 * The account's second factor, through core's own challenge. At login the
 * challenge is requested for the session; core's login chain asks for it
 * anyway, and any other login is held at the challenge by core's two-factor
 * middleware. The login stays pending until the challenge is passed
 * ({@see \OCA\IntrusionDetection\Listener\ChallengePassedListener}),
 * so a login stopped at the challenge is never counted as confirmed.
 *
 * Only a second factor that is set up counts: an account for which two
 * factors are enforced but that has no provider yet would set one up with
 * just the password, which proves nothing. Neither does a provider set up
 * from a session that proved only the password, for a while or until it
 * is set up again ({@see UntrustedSecondFactors}).
 */
class SecondFactorMethod implements IConfirmationMethod {
	public function __construct(
		private readonly IChallengeRequester $challenges,
		private readonly AccountMethods $methods,
	) {
	}

	#[\Override]
	public function id(): string {
		return self::SECOND_FACTOR;
	}

	#[\Override]
	public function isAvailable(IUser $user, StepUpPolicy $policy): bool {
		return $this->challenges->isAvailable($user) && $this->methods->bySecondFactor($user);
	}

	#[\Override]
	public function isAvailableInBrowser(IUser $user, StepUpPolicy $policy): bool {
		return $this->isAvailable($user, $policy);
	}

	#[\Override]
	public function begin(IUser $user, StepUpState $state): string {
		try {
			$this->challenges->requestChallenge($user, '');
		} catch (\LogicException) {
			return self::UNAVAILABLE;
		}
		$state->secondFactorRequested = true;
		// Other methods would need to be started now (an email code): this one is answered at core's challenge.
		$state->methods = [self::SECOND_FACTOR];
		return self::PENDING;
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
