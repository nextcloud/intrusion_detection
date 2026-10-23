<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm\Reasons;

use OCA\IntrusionDetection\Confirm\IStepUpReason;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Login\LoginContext;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\TrustedNetwork\ITrustedNetworks;

/**
 * The address or its network is flagged after an attack (concept section
 * 11.9), and it is not one of the user's trusted networks. One query on the
 * flags; the trusted networks are only read for a flagged address.
 */
class FlaggedSourceReason implements IStepUpReason {
	public function __construct(
		private readonly FlaggedSources $flags,
		private readonly ITrustedNetworks $trustedNetworks,
	) {
	}

	#[\Override]
	public static function policy(): StepUpPolicy {
		return StepUpPolicy::FlaggedSource;
	}

	#[\Override]
	public function applies(LoginContext $login): bool {
		if ($login->source === null || $this->flags->sourceFlag($login->source) === null) {
			return false;
		}
		return !$this->trustedNetworks->isTrusted($login->uid(), $login->source);
	}
}
