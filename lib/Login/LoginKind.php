<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Login;

/**
 * How a request logged in, as {@see LoginClassifier} tells it from core's
 * login event and the credentials core used.
 */
enum LoginKind: string {
	/** The login form, through core's login chain (`POST /login`) */
	case FormPassword = 'form_password';
	/** An app or script that sends the account's password with Basic auth */
	case ClientPassword = 'client_password';
	/** Any other login with a password, such as an SSO backend that hands core a stored secret */
	case OtherPassword = 'other_password';
	/** Single sign-on and other logins without a password (WebAuthn) */
	case Sso = 'sso';
	/** An app password sent with Basic auth */
	case AppPasswordBasic = 'app_password_basic';
	/** A token in an `Authorization: Bearer` header */
	case Bearer = 'bearer';
	/** A browser session that core restored from its own session token */
	case RestoredSession = 'restored_session';
	/** A browser that came back with its remember-me cookie */
	case RememberMeCookie = 'remember_me_cookie';

	/**
	 * A login with the account's password.
	 */
	public function hasPassword(): bool {
		return match ($this) {
			self::FormPassword, self::ClientPassword, self::OtherPassword => true,
			default => false,
		};
	}

	/**
	 * A login with the password that a person may have typed: the login
	 * form, and every password login that is not Basic auth. An unknown
	 * way in is treated like the login form, so that it never skips a check.
	 */
	public function typesPassword(): bool {
		return $this === self::FormPassword || $this === self::OtherPassword;
	}

	/**
	 * A person who logs in with a browser: the login form, another login
	 * with a password, or single sign-on.
	 */
	public function isInteractive(): bool {
		return $this->typesPassword() || $this === self::Sso;
	}

	/**
	 * An app or script that sends its credential with every request, and
	 * so logs in with every request.
	 */
	public function isClient(): bool {
		return match ($this) {
			self::ClientPassword, self::AppPasswordBasic, self::Bearer => true,
			default => false,
		};
	}

	/**
	 * A login whose session is a browser's: its session token exists after
	 * the login, and is linked to what the login recorded on its first request.
	 */
	public function isBrowser(): bool {
		return !$this->isClient();
	}

	/**
	 * A session that comes back with a token or a cookie, rather than a new login.
	 */
	public function isReturning(): bool {
		return match ($this) {
			self::AppPasswordBasic, self::Bearer, self::RestoredSession, self::RememberMeCookie => true,
			default => false,
		};
	}
}
