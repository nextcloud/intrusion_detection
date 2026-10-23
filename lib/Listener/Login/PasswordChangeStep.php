<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener\Login;

use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCA\IntrusionDetection\SessionState\Rules\PasswordChangeRule;
use OCA\IntrusionDetection\SessionState\SessionState;

/**
 * At each login of an account that must choose a new password, marks the
 * session for {@see PasswordChangeRule}, in the mode for its kind of login
 * ({@see PasswordChangeRule::modeFor()}).
 *
 * An account whose password is managed outside Nextcloud is not marked;
 * the administrators are asked to reset it instead.
 */
class PasswordChangeStep implements ILoginStep {
	public function __construct(
		private readonly PasswordChangeService $passwords,
		private readonly SessionState $state,
	) {
	}

	#[\Override]
	public static function appliesTo(LoginFacts $facts): bool {
		return PasswordChangeRule::modeFor($facts->kind) !== null;
	}

	#[\Override]
	public function handle(LoginFacts $facts): void {
		$since = $this->passwords->requiredSince($facts->uid());
		if ($since === null) {
			return;
		}
		if (!$facts->user->canChangePassword()) {
			$this->passwords->external($facts->user);
			return;
		}
		$this->state->set(SessionState::PASSWORD_CHANGE, ['uid' => $facts->uid(), 'mode' => PasswordChangeRule::modeFor($facts->kind), 'since' => $since]);
	}
}
