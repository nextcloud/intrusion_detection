<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\CredentialUse;

use OCP\IRequest;

/**
 * The one credential a request presents to log in, read before anything is
 * verified, in the order core tries them: a Bearer token, then Basic
 * credentials, then the session cookie.
 *
 * - Basic: only the password part identifies the credential, whatever it is
 *   (the login password or an app password; nothing can tell them apart
 *   before authentication). The login name only adds a short tag, so two
 *   accounts that happen to share a password are not taken for one
 *   credential.
 * - Bearer: the token. An app password sent as a Bearer token is the same
 *   credential as when it is sent with Basic.
 * - The session cookie, named after the instance id. Its value is the PHP
 *   session id, which is also the secret of the session's token.
 *
 * The secret never leaves this object except as HMAC input
 * ({@see self::keyMaterial()}) and through constant-time comparison.
 */
final class PresentedCredential {
	public const SCHEME_BASIC = 'basic';
	public const SCHEME_BEARER = 'bearer';
	public const SCHEME_SESSION = 'session';

	/**
	 * @param self::SCHEME_* $scheme
	 */
	private function __construct(
		public readonly string $scheme,
		#[\SensitiveParameter]
		private readonly string $secret,
		/** The login name of Basic credentials, empty otherwise */
		public readonly string $basicUser,
		/** Whether the request also carries the session cookie */
		public readonly bool $hasSessionCookie,
	) {
	}

	/**
	 * @param string $sessionCookieName the instance id, which names the session cookie
	 */
	public static function fromRequest(IRequest $request, string $sessionCookieName): ?self {
		$cookie = self::sessionCookieOf($request, $sessionCookieName);
		$authorization = trim($request->getHeader('Authorization'));

		if (strncasecmp($authorization, 'Bearer ', 7) === 0) {
			$token = trim(substr($authorization, 7));
			if ($token !== '') {
				return new self(self::SCHEME_BEARER, $token, '', $cookie !== null);
			}
		}

		$user = $request->getHeader('PHP_AUTH_USER');
		$password = $request->getHeader('PHP_AUTH_PW');
		if ($password === '' && strncasecmp($authorization, 'Basic ', 6) === 0) {
			$decoded = base64_decode(trim(substr($authorization, 6)), true);
			$parts = is_string($decoded) ? explode(':', $decoded, 2) : [];
			if (count($parts) === 2) {
				[$user, $password] = $parts;
			}
		}
		// Core ignores Basic credentials with an empty name or password.
		if ($user !== '' && $password !== '') {
			return new self(self::SCHEME_BASIC, $password, $user, $cookie !== null);
		}

		return $cookie;
	}

	/**
	 * The session cookie alone, whatever else the request carries.
	 */
	public static function sessionCookieOf(IRequest $request, string $sessionCookieName): ?self {
		$cookie = $sessionCookieName === '' ? null : $request->getCookie($sessionCookieName);
		return is_string($cookie) && $cookie !== '' ? new self(self::SCHEME_SESSION, $cookie, '', true) : null;
	}

	/**
	 * What the credential key is derived from. The same app password gives
	 * the same material over Basic and Bearer.
	 */
	public function keyMaterial(): string {
		return ($this->scheme === self::SCHEME_SESSION ? "session\0" : "password\0") . $this->secret;
	}

	/**
	 * A short, non-secret tag of the Basic login name, so that switches are
	 * only counted between uses by the same account. Empty for Bearer tokens
	 * and sessions, which name no account; an empty tag matches any.
	 */
	public function userTag(): string {
		return $this->basicUser === '' ? '' : hash('crc32b', mb_strtolower(trim($this->basicUser)));
	}

	/**
	 * Whether the secret equals a value (the session's app password, or
	 * the session id), compared in constant time.
	 */
	public function matches(#[\SensitiveParameter] ?string $value): bool {
		return $value !== null && $value !== '' && hash_equals($value, $this->secret);
	}

	/**
	 * @return array{scheme: string}
	 */
	public function __debugInfo(): array {
		return ['scheme' => $this->scheme];
	}
}
