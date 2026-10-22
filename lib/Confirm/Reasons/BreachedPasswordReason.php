<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm\Reasons;

use OCA\IntrusionDetection\Check\Checks\BreachedPassword\BreachedPassword;
use OCA\IntrusionDetection\Check\Checks\BreachedPassword\BreachedPasswordDetector;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Confirm\IStepUpReason;
use OCA\IntrusionDetection\Confirm\LoginContext;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Definition\ResponseType;
use Psr\Container\ContainerInterface;

/**
 * The account's current password was found on the breach list (concept
 * section 10.5), and the breach check acts and has the step-up response.
 * The stored result is read (one user value); the list itself is only
 * contacted by the check's own login handling.
 */
class BreachedPasswordReason implements IStepUpReason {
	public function __construct(
		private readonly CheckSettings $settings,
		private readonly ContainerInterface $container,
	) {
	}

	#[\Override]
	public static function policy(): StepUpPolicy {
		return StepUpPolicy::BreachedPassword;
	}

	#[\Override]
	public function applies(LoginContext $login): bool {
		// Off by default: stop before loading the detector and its HTTP client.
		if (!$this->settings->modeState(BreachedPassword::ID)->acts()
			|| !$this->settings->hasResponse(BreachedPassword::ID, ResponseType::StepUp)) {
			return false;
		}
		return $this->container->get(BreachedPasswordDetector::class)->isBreached($login->user);
	}
}
