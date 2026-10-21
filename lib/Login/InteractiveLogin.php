<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Login;

use OCP\IRequest;
use OCP\User\Events\UserLoggedInEvent;

/**
 * Tells how a successful login with the account's password reached core.
 *
 * `UserLoggedInEvent` fires for every login, and its `isTokenLogin()` only
 * covers app passwords and tokens. Request headers are the client's to
 * choose, so they never decide:
 *
 * - {@see self::CLIENT}: an app or script sent the password with Basic
 *   auth. Only the credentials PHP and core put into `$_SERVER` count, and
 *   only when they are the ones the login used.
 * - {@see self::FORM}: the login form, through core's login chain
 *   (`POST /login`).
 * - {@see self::OTHER}: any other login with a password, such as an SSO
 *   backend that hands core a stored secret. It is treated like the login
 *   form, so that an unknown way in never skips a check.
 */
class InteractiveLogin {
	public const LOGIN_PATH = '/login';

	public const FORM = 'form';
	public const CLIENT = 'client';
	public const OTHER = 'other';

	public function __construct(
		private readonly IRequest $request,
	) {
	}

	/**
	 * @return self::FORM|self::CLIENT|self::OTHER|null null without a password (tokens, app passwords, passwordless and SSO logins)
	 */
	public function kind(UserLoggedInEvent $event): ?string {
		if ($event->isTokenLogin()) {
			return null;
		}
		$password = $event->getPassword();
		if ($password === null || $password === '') {
			return null;
		}
		$basic = self::basicPassword();
		if ($basic !== null && hash_equals($basic, $password)) {
			return self::CLIENT;
		}
		return $this->isLoginForm() ? self::FORM : self::OTHER;
	}

	/**
	 * A login with the password that a person may have typed: the login
	 * form, and every password login that is not Basic auth.
	 */
	public function isPasswordLogin(UserLoggedInEvent $event): bool {
		$kind = $this->kind($event);
		return $kind === self::FORM || $kind === self::OTHER;
	}

	/**
	 * Whether the request carries Basic credentials, as PHP or core's
	 * `OC::handleAuthHeaders()` put them into `$_SERVER`.
	 */
	public static function hasBasicCredentials(): bool {
		return self::basicPassword() !== null;
	}

	private static function basicPassword(): ?string {
		return BasicCredentials::fromServer()[1] ?? null;
	}

	private function isLoginForm(): bool {
		try {
			return $this->request->getMethod() === 'POST' && $this->request->getPathInfo() === self::LOGIN_PATH;
		} catch (\Throwable) {
			return false;
		}
	}
}
