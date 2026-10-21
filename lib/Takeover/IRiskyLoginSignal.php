<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Takeover;

/**
 * One way to tell that the login of a session was risky, for the account
 * takeover check (concept section 10.14). Implementations are listed in
 * {@see RiskyLogins::SIGNALS}.
 *
 * Signals are asked only after a security change, never on normal requests.
 */
interface IRiskyLoginSignal {
	/**
	 * The risky login of this account's session, or null when this signal
	 * sees nothing risky about it.
	 *
	 * @param ?int $sessionTokenId the session (or app password) the change was made with
	 */
	public function riskyLogin(string $uid, ?int $sessionTokenId): ?RiskyLogin;
}
