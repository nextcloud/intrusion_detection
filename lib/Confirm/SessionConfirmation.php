<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Login\CoreSession;

/**
 * How much the current session's login proved, for decisions a session
 * makes about its own account ("Was this you?", a new second factor):
 *
 * - {@see self::UNCONFIRMED}: the login waits for its confirmation, was
 *   refused, or was let in without one (`confirmed_by = none`), or the
 *   request uses an app password;
 * - {@see self::PROVEN}: beyond the password, the login proved a second
 *   factor, an email code, an administrator's approval or a known device;
 * - {@see self::PASSWORD}: a login that needed no confirmation.
 *
 * "No, it was not me" asks {@see self::denialLevel()} instead, which counts
 * an app password as the password.
 *
 * Read from the session only: no query.
 */
class SessionConfirmation {
	public const UNCONFIRMED = 'unconfirmed';
	public const PASSWORD = 'password';
	public const PROVEN = 'proven';

	public function __construct(
		private readonly LoginConfirmationStore $store,
		private readonly CoreSession $coreSession,
	) {
	}

	/**
	 * @return self::UNCONFIRMED|self::PASSWORD|self::PROVEN
	 */
	public function level(string $uid): string {
		return $this->isAppPassword() ? self::UNCONFIRMED : $this->loginLevel($uid);
	}

	/**
	 * The level for "No, it was not me". A "No" can only make the account
	 * safer, and the Nextcloud apps send it with their app password, so an
	 * app password counts as {@see self::PASSWORD}, never more. A login
	 * that waits for its confirmation, was refused, or was let in without
	 * one stays {@see self::UNCONFIRMED}.
	 *
	 * @return self::UNCONFIRMED|self::PASSWORD|self::PROVEN
	 */
	public function denialLevel(string $uid): string {
		$level = $this->loginLevel($uid);
		return $level === self::PROVEN && $this->isAppPassword() ? self::PASSWORD : $level;
	}

	public function isUnconfirmed(string $uid): bool {
		return $this->level($uid) === self::UNCONFIRMED;
	}

	public function isProven(string $uid): bool {
		return $this->level($uid) === self::PROVEN;
	}

	/**
	 * What the session's login proved, whatever the request authenticated with.
	 *
	 * @return self::UNCONFIRMED|self::PASSWORD|self::PROVEN
	 */
	private function loginLevel(string $uid): string {
		return $this->store->of($uid)->level();
	}

	private function isAppPassword(): bool {
		return $this->coreSession->usesAppPassword();
	}
}
