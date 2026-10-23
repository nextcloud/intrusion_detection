<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener\Login;

use OCA\IntrusionDetection\Confirm\Administrators;
use OCA\IntrusionDetection\Login\LoginKind;
use OCA\IntrusionDetection\Login\SessionMarkers;

/**
 * Marks the browser session of an administrator's login, so that the
 * session rule ({@see \OCA\IntrusionDetection\SessionState\Rules\AdminNetworkRule})
 * holds it to "administrators from trusted networks only" while it lasts:
 * logins with the password, and sessions that come back with their
 * remember-me cookie or their session token. Single sign-on is left to
 * its identity provider: it could never confirm a login from outside.
 * Marked whatever the switch says, so that switching it on covers the
 * sessions that exist.
 */
class AdminSessionStep implements ILoginStep {
	public function __construct(
		private readonly SessionMarkers $markers,
		private readonly Administrators $administrators,
	) {
	}

	#[\Override]
	public static function appliesTo(LoginFacts $facts): bool {
		return $facts->kind->typesPassword() || $facts->kind === LoginKind::RememberMeCookie || $facts->kind === LoginKind::RestoredSession;
	}

	#[\Override]
	public function handle(LoginFacts $facts): void {
		if ($this->administrators->isAdministrator($facts->user)) {
			$this->markers->set(SessionMarkers::ADMIN_SESSION, ['uid' => $facts->uid()]);
		}
	}
}
