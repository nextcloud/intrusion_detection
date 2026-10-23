<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener\Login;

use OCA\IntrusionDetection\LoginHistory\LoginHistory;

/**
 * Writes the login history (concept section 12.2, step 2): how the account
 * logged in, from where, and how the step-up decided. A browser session
 * restored from its session token is the same session, not a new login,
 * and is not recorded.
 */
class HistoryStep implements ILoginStep {
	public function __construct(
		private readonly LoginHistory $history,
	) {
	}

	#[\Override]
	public static function appliesTo(LoginFacts $facts): bool {
		return LoginHistory::methodOf($facts->kind) !== null && $facts->isRecorded() && !$facts->isBypassListed();
	}

	#[\Override]
	public function handle(LoginFacts $facts): void {
		$method = LoginHistory::methodOf($facts->kind);
		if ($method === null) {
			return;
		}
		[$confirmedBy, $stepUp] = $facts->confirmation?->historyOutcome() ?? [LoginHistory::CONFIRMED_BY_NONE, null];
		$this->history->record($facts->uid(), $method, $facts->source, $facts->userAgent, $facts->device !== null, $facts->kind->isBrowser(), $confirmedBy, $stepUp, $facts->firstOfTheHour());
	}
}
