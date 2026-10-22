<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm\Reasons;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\IStepUpReason;
use OCA\IntrusionDetection\Confirm\LoginContext;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\TrustedNetwork\ITrustedNetworks;

/**
 * The address has a high risk score (concept section 10.18): every
 * successful password login from it needs extra confirmation. Nothing is
 * read while the risk score is off, while protection is off or learning
 * (the other reasons follow their checks' modes; this one has no check),
 * or for a network the user confirmed as theirs ("Yes, it was me");
 * otherwise the score's three indexed queries, cached per address for a
 * minute.
 */
class RiskHighReason implements IStepUpReason {
	public function __construct(
		private readonly RiskScorer $risk,
		private readonly AppSettings $settings,
		private readonly ITrustedNetworks $trustedNetworks,
	) {
	}

	#[\Override]
	public static function policy(): StepUpPolicy {
		return StepUpPolicy::RiskHigh;
	}

	#[\Override]
	public function applies(LoginContext $login): bool {
		if ($login->source === null || !$this->risk->isEnabled() || !$this->settings->isEnabled() || $this->settings->isLearning()) {
			return false;
		}
		return $this->risk->score($login->source)->isHigh() && !$this->trustedNetworks->isTrusted($login->uid(), $login->source);
	}
}
