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
use OCA\IntrusionDetection\Lockdown\LockdownEffect;
use OCA\IntrusionDetection\Lockdown\LockdownState;

/**
 * Lockdown mode is on (concept section 11.14): every password login needs
 * extra confirmation, from every address. Reads the app config only.
 */
class LockdownReason implements IStepUpReason {
	public function __construct(
		private readonly LockdownState $lockdown,
	) {
	}

	#[\Override]
	public static function policy(): StepUpPolicy {
		return StepUpPolicy::Lockdown;
	}

	#[\Override]
	public function applies(LoginContext $login): bool {
		return $this->lockdown->applies(LockdownEffect::Login);
	}
}
