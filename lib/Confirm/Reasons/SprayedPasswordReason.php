<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm\Reasons;

use OCA\IntrusionDetection\Check\Checks\PasswordSpraying;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\IStepUpReason;
use OCA\IntrusionDetection\Confirm\LoginContext;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;

/**
 * The password is flagged as sprayed (concept section 10.2), and the
 * password spraying check acts and has the step-up response. The flag was
 * looked up once for the login; nothing is read here.
 */
class SprayedPasswordReason implements IStepUpReason {
	public function __construct(
		private readonly Settings $settings,
	) {
	}

	#[\Override]
	public static function policy(): StepUpPolicy {
		return StepUpPolicy::SprayedPassword;
	}

	#[\Override]
	public function applies(LoginContext $login): bool {
		return $login->passwordFlagged
			&& $this->settings->modeState(PasswordSpraying::ID)->acts()
			&& $this->settings->hasResponse(PasswordSpraying::ID, ResponseType::StepUp);
	}
}
