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
use OCA\IntrusionDetection\Risk\RiskScorer;

/**
 * The address has a high risk score (concept section 10.18): every
 * successful password login from it needs extra confirmation. Nothing is
 * read while the risk score is off; otherwise the score's three indexed
 * queries, cached per address for a minute.
 */
class RiskHighReason implements IStepUpReason {
	public function __construct(
		private readonly RiskScorer $risk,
	) {
	}

	#[\Override]
	public static function policy(): StepUpPolicy {
		return StepUpPolicy::RiskHigh;
	}

	#[\Override]
	public function applies(LoginContext $login): bool {
		return $login->source !== null && $this->risk->isEnabled() && $this->risk->score($login->source)->isHigh();
	}
}
