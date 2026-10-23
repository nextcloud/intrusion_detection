<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailedRule;

/**
 * What a step of a pending login on the verify page led to
 * ({@see PendingLoginFlow}).
 */
enum PendingLoginResult {
	/** No login of this account waits: the session goes on */
	case NotPending;
	/** The login is confirmed */
	case Confirmed;
	/** The login waits for an administrator */
	case Waiting;
	/** The login cannot be confirmed this way */
	case Unavailable;
	/** It could not be started now; another try may work */
	case NotStarted;
	case CodeSent;
	/** The email with a new code could not be sent */
	case CodeNotSent;
	/** The account got too many codes within the hour */
	case TooManyCodes;
	/** No new code may be sent for a few minutes */
	case NoResendYet;
	case WrongCode;
	case ExpiredCode;
	case MalformedCode;
	/** Ended: the code was entered wrong too many times */
	case EndedAttempts;
	/** Ended: an administrator rejected the login */
	case EndedRejected;
	/** Ended: the request for approval expired */
	case EndedTimeout;

	/**
	 * The rule the login ended with, or null when it goes on.
	 */
	public function endedRule(): ?StepUpFailedRule {
		return match ($this) {
			self::EndedAttempts => StepUpFailedRule::Attempts,
			self::EndedRejected => StepUpFailedRule::Rejected,
			self::EndedTimeout => StepUpFailedRule::Timeout,
			default => null,
		};
	}
}
