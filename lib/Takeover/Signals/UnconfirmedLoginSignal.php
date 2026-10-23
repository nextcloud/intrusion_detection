<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Takeover\Signals;

use OCA\IntrusionDetection\Confirm\LoginConfirmation;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Takeover\IRiskyLoginSignal;
use OCA\IntrusionDetection\Takeover\RiskyLogin;

/**
 * The current session's login needed a confirmation (a step-up reason),
 * and still waits for it (a change made at a page the pending login may
 * reach, such as core's second-factor setup) or the policies let it in
 * without one (`confirmed_by = none`). How the
 * login was confirmed is kept in the session ({@see SessionMarkers::CONFIRMATION});
 * a login confirmed with a second factor or an email code is not risky.
 *
 * Only the current request's session is known here, so a change made with
 * another session is not judged by this signal.
 */
class UnconfirmedLoginSignal implements IRiskyLoginSignal {
	public function __construct(
		private readonly SessionMarkers $state,
		private readonly CoreSession $coreSession,
	) {
	}

	#[\Override]
	public function riskyLogin(string $uid, ?int $sessionTokenId): ?RiskyLogin {
		if ($sessionTokenId === null || $this->coreSession->tokenId() !== $sessionTokenId) {
			return null;
		}
		$login = LoginConfirmation::fromMarkers($this->state->all(), $uid);
		return $login->isRisky() ? new RiskyLogin($login->since, RiskyLogin::REASON_UNCONFIRMED, $login->policies) : null;
	}
}
