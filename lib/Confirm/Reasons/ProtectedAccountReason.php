<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm\Reasons;

use OCA\IntrusionDetection\Confirm\IStepUpReason;
use OCA\IntrusionDetection\Confirm\LoginContext;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Response\AccountProtection;

/**
 * The account is under extra protection because its password is being
 * guessed (concept section 11.6). One primary-key read, cached for a minute.
 */
class ProtectedAccountReason implements IStepUpReason {
	public function __construct(
		private readonly AccountProtection $protection,
	) {
	}

	#[\Override]
	public static function policy(): StepUpPolicy {
		return StepUpPolicy::ProtectedAccount;
	}

	#[\Override]
	public function applies(LoginContext $login): bool {
		return $this->protection->isProtected($login->uid());
	}
}
