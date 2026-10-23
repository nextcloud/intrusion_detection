<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Login;

use OCP\IRequest;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;

/**
 * Tells how a successful login reached core ({@see LoginKind}), once per
 * login event; the answer is kept in the {@see RequestContext}.
 *
 * `UserLoggedInEvent` fires for every login, and its `isTokenLogin()`
 * covers app passwords, tokens and restored browser sessions. Request
 * headers are the client's to choose, so they decide only what core
 * decided by them:
 *
 * - core takes a token from an `Authorization: Bearer` header,
 *   case-sensitively, so this test is case-sensitive too;
 * - Basic credentials count only as PHP and core put them into `$_SERVER`
 *   ({@see BasicCredentials}), and a password login is an app's only when
 *   they carry the password the login used;
 * - the login form is core's login chain (`POST /login`).
 */
class LoginClassifier {
	public const LOGIN_PATH = '/login';
	private const CONTEXT_KEY = 'login.kind';

	public function __construct(
		private readonly IRequest $request,
		private readonly RequestContext $context,
	) {
	}

	public function classify(UserLoggedInEvent|UserLoggedInWithCookieEvent $event): LoginKind {
		$known = $this->context->get(self::CONTEXT_KEY);
		if (is_array($known) && ($known[0] ?? null) === $event && ($known[1] ?? null) instanceof LoginKind) {
			return $known[1];
		}
		$kind = $this->kindOf($event);
		$this->context->set(self::CONTEXT_KEY, [$event, $kind]);
		return $kind;
	}

	private function kindOf(UserLoggedInEvent|UserLoggedInWithCookieEvent $event): LoginKind {
		if ($event instanceof UserLoggedInWithCookieEvent) {
			return LoginKind::RememberMeCookie;
		}
		if ($event->isTokenLogin()) {
			if (str_starts_with($this->request->getHeader('Authorization'), 'Bearer ')) {
				return LoginKind::Bearer;
			}
			return BasicCredentials::fromServer() !== null ? LoginKind::AppPasswordBasic : LoginKind::RestoredSession;
		}
		$password = $event->getPassword();
		if ($password === null || $password === '') {
			return LoginKind::Sso;
		}
		$basic = BasicCredentials::fromServer()[1] ?? null;
		if ($basic !== null && hash_equals($basic, $password)) {
			return LoginKind::ClientPassword;
		}
		return $this->isLoginForm() ? LoginKind::FormPassword : LoginKind::OtherPassword;
	}

	private function isLoginForm(): bool {
		try {
			return $this->request->getMethod() === 'POST' && $this->request->getPathInfo() === self::LOGIN_PATH;
		} catch (\Throwable) {
			return false;
		}
	}
}
