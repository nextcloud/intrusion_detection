<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm\Reasons;

use OCA\IntrusionDetection\Check\Checks\RiskyNetwork\RiskyNetwork;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Confirm\IStepUpReason;
use OCA\IntrusionDetection\Confirm\LoginContext;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Risk\NetworkAttributes;

/**
 * The login comes from a hosting or Tor network (concept section 10.17),
 * and the check acts and has the step-up response. Office networks, exempt
 * groups and the user's trusted networks never apply
 * ({@see NetworkAttributes}). The attributes come from the address check's
 * verdict, so an ordinary address costs nothing.
 */
class RiskyNetworkReason implements IStepUpReason {
	public function __construct(
		private readonly CheckSettings $settings,
		private readonly NetworkAttributes $networks,
	) {
	}

	#[\Override]
	public static function policy(): StepUpPolicy {
		return StepUpPolicy::RiskyNetwork;
	}

	#[\Override]
	public function applies(LoginContext $login): bool {
		return $this->settings->modeState(RiskyNetwork::ID)->acts()
			&& $this->settings->hasResponse(RiskyNetwork::ID, ResponseType::StepUp)
			&& $this->networks->riskyLogin($login) !== null;
	}
}
