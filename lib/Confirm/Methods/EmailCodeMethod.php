<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm\Methods;

use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCP\IUser;

/**
 * A 6-digit code sent to the account's email address; see {@see EmailCodes}.
 * The first code is sent at login. Accounts without an email address never
 * get one offered, and never cause an email.
 */
class EmailCodeMethod implements IConfirmationMethod {
	public function __construct(
		private readonly EmailCodes $codes,
	) {
	}

	#[\Override]
	public function id(): string {
		return self::EMAIL_CODE;
	}

	#[\Override]
	public function isAvailable(IUser $user, StepUpPolicy $policy): bool {
		return $this->codes->isAvailable($user);
	}

	#[\Override]
	public function begin(IUser $user, StepUpState $state): string {
		return $this->codes->issue($user, $state) ? self::PENDING : self::UNAVAILABLE;
	}
}
