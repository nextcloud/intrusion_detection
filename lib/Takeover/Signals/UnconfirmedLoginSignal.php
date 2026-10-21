<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Takeover\Signals;

use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\Takeover\IRiskyLoginSignal;
use OCA\IntrusionDetection\Takeover\RiskyLogin;

/**
 * The current session's login needed a confirmation (a step-up reason),
 * and still waits for it (a change made at a page the pending login may
 * reach, such as core's second-factor setup) or the policies let it in
 * without one (`confirmed_by = none`). How the
 * login was confirmed is kept in the session ({@see SessionState::CONFIRMATION});
 * a login confirmed with a second factor or an email code is not risky.
 *
 * Only the current request's session is known here, so a change made with
 * another session is not judged by this signal.
 */
class UnconfirmedLoginSignal implements IRiskyLoginSignal {
	public function __construct(
		private readonly SessionState $state,
		private readonly CurrentSession $currentSession,
	) {
	}

	#[\Override]
	public function riskyLogin(string $uid, ?int $sessionTokenId): ?RiskyLogin {
		if ($sessionTokenId === null || $this->currentSession->tokenId() !== $sessionTokenId) {
			return null;
		}
		$stepUp = StepUpState::fromArray($this->state->get(SessionState::STEP_UP) ?? []);
		if ($stepUp !== null && $stepUp->uid === $uid) {
			return new RiskyLogin($stepUp->started, RiskyLogin::REASON_UNCONFIRMED, $stepUp->policies);
		}
		$confirmation = $this->state->get(SessionState::CONFIRMATION);
		if ($confirmation === null || ($confirmation['uid'] ?? null) !== $uid || ($confirmation['by'] ?? null) !== StepUpService::CONFIRMED_BY_NONE) {
			return null;
		}
		$at = $confirmation['at'] ?? null;
		$policies = is_array($confirmation['policies'] ?? null) ? array_values(array_filter($confirmation['policies'], 'is_string')) : [];
		return is_int($at) ? new RiskyLogin($at, RiskyLogin::REASON_UNCONFIRMED, $policies) : null;
	}
}
