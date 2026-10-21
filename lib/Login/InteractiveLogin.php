<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Login;

use OCP\IRequest;
use OCP\ISession;
use OCP\User\Events\UserLoggedInEvent;

/**
 * Tells an interactive password login (a person typing the account's
 * password into the login form) from every other successful login.
 *
 * `UserLoggedInEvent` fires for all of them, and its `isTokenLogin()` only
 * covers app passwords and tokens. A client that sends the real password
 * with Basic auth (WebDAV, OCS, CORS) also looks like a password login, and
 * so does an SSO backend that hands core a stored secret. Only the login
 * form reaches core through `POST /login`, the login chain, without an
 * `Authorization` header; that is what is checked here.
 */
class InteractiveLogin {
	public const LOGIN_PATH = '/login';

	public function __construct(
		private readonly IRequest $request,
		private readonly ISession $session,
	) {
	}

	public function isPasswordLogin(UserLoggedInEvent $event): bool {
		if ($event->isTokenLogin()) {
			return false;
		}
		$password = $event->getPassword();
		if ($password === null || $password === '') {
			return false;
		}
		if ($this->request->getHeader('Authorization') !== '' || $this->request->getHeader('PHP_AUTH_USER') !== '') {
			return false;
		}
		if ($this->session->exists('app_password')) {
			return false;
		}
		if ($this->request->getMethod() !== 'POST') {
			return false;
		}
		try {
			return $this->request->getPathInfo() === self::LOGIN_PATH;
		} catch (\Throwable) {
			return false;
		}
	}
}
