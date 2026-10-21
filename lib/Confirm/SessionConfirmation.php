<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ISession;

/**
 * How much the current session's login proved, for decisions a session
 * makes about its own account ("Was this you?", a new second factor):
 *
 * - {@see self::UNCONFIRMED}: the login waits for its confirmation, was
 *   refused, or was let in without one (`confirmed_by = none`), or the
 *   request uses an app password;
 * - {@see self::PROVEN}: beyond the password, the login proved a second
 *   factor, an email code, an administrator's approval or a known device;
 * - {@see self::PASSWORD}: a login that needed no confirmation.
 *
 * Read from the session only: no query.
 */
class SessionConfirmation {
	public const UNCONFIRMED = 'unconfirmed';
	public const PASSWORD = 'password';
	public const PROVEN = 'proven';

	/** The confirmation methods that prove more than the password */
	public const PROOFS = [
		IConfirmationMethod::SECOND_FACTOR,
		IConfirmationMethod::EMAIL_CODE,
		IConfirmationMethod::ADMIN_APPROVAL,
		IConfirmationMethod::KNOWN_DEVICE,
	];

	public function __construct(
		private readonly SessionState $state,
		private readonly ISession $session,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return self::UNCONFIRMED|self::PASSWORD|self::PROVEN
	 */
	public function level(string $uid): string {
		if ($this->isAppPassword()) {
			return self::UNCONFIRMED;
		}
		$stepUp = $this->state->get(SessionState::STEP_UP);
		if ($stepUp !== null && ($stepUp['uid'] ?? null) === $uid) {
			return self::UNCONFIRMED;
		}
		$confirmation = $this->state->get(SessionState::CONFIRMATION);
		if ($confirmation !== null && ($confirmation['uid'] ?? null) === $uid) {
			$by = $confirmation['by'] ?? null;
			if ($by === StepUpService::CONFIRMED_BY_NONE) {
				return self::UNCONFIRMED;
			}
			if (in_array($by, self::PROOFS, true)) {
				return self::PROVEN;
			}
		}
		$proof = $this->state->get(SessionState::PROOF);
		if ($proof !== null && ($proof['uid'] ?? null) === $uid && in_array($proof['by'] ?? null, self::PROOFS, true)) {
			return self::PROVEN;
		}
		return self::PASSWORD;
	}

	public function isUnconfirmed(string $uid): bool {
		return $this->level($uid) === self::UNCONFIRMED;
	}

	public function isProven(string $uid): bool {
		return $this->level($uid) === self::PROVEN;
	}

	/**
	 * A login that needed no step-up proved more than the password anyway:
	 * core's second factor, or a known device.
	 *
	 * @param IConfirmationMethod::SECOND_FACTOR|IConfirmationMethod::KNOWN_DEVICE $by
	 */
	public function proved(string $uid, string $by): void {
		$this->state->set(SessionState::PROOF, ['uid' => $uid, 'by' => $by, 'at' => $this->timeFactory->getTime()]);
	}

	private function isAppPassword(): bool {
		try {
			return $this->session->exists('app_password');
		} catch (\Throwable) {
			return true;
		}
	}
}
