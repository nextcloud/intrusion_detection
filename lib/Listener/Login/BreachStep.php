<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener\Login;

use OCA\IntrusionDetection\Signal\InteractivePasswordLogin;
use OCA\IntrusionDetection\Signal\SignalDispatcher;

/**
 * Checks a password a person typed against the breach list, when the check
 * runs and the account is due (concept section 10.5). Logins with app
 * passwords and tokens, and clients that send the password with Basic
 * auth, are never checked.
 */
class BreachStep implements ILoginStep {
	public function __construct(
		private readonly SignalDispatcher $dispatcher,
	) {
	}

	#[\Override]
	public static function appliesTo(LoginFacts $facts): bool {
		return $facts->kind->typesPassword();
	}

	#[\Override]
	public function handle(LoginFacts $facts): void {
		$this->dispatcher->dispatch(new InteractivePasswordLogin($facts->user, (string)$facts->event->getPassword(), $facts->userAgent));
	}
}
