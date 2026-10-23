<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener\Login;

use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Confirm\LoginAssessment;
use OCA\IntrusionDetection\Login\LoginKind;

/**
 * Decides whether a login with the password needs extra confirmation
 * ({@see LoginAssessment}); from an address on the brute-force allowlist
 * by the explicit rules only. It checks a session that comes back while
 * unconfirmed sessions may exist. First, so that a new password it
 * requires is picked up by the password change step at once, and the
 * history records how the login was confirmed.
 */
class StepUpStep implements ILoginStep {
	public function __construct(
		private readonly LoginAssessment $assessment,
	) {
	}

	#[\Override]
	public static function appliesTo(LoginFacts $facts): bool {
		return $facts->kind->hasPassword() || ($facts->kind->isReturning() && $facts->mayResume());
	}

	#[\Override]
	public function handle(LoginFacts $facts): void {
		if ($facts->kind->isReturning()) {
			$facts->confirmation = $this->assessment->returning($facts->uid(), $facts->kind);
			return;
		}
		$password = $facts->event->getPassword();
		if ($password === null) {
			return;
		}
		$allowlisted = $facts->isBypassListed();
		$confirmation = $this->assessment->passwordLogin($facts->user, $password, $facts->kind !== LoginKind::ClientPassword, $facts->source, $facts->userAgent, $allowlisted);
		if (!$allowlisted || $confirmation->status !== ConfirmationStatus::None) {
			$facts->confirmation = $confirmation;
		}
	}
}
