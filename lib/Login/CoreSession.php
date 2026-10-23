<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Login;

use OCP\Authentication\Token\IProvider;
use OCP\ISession;
use Psr\Log\LoggerInterface;

/**
 * What core keeps in the session about how it was logged in: the session
 * id, the app password and the id of the token a request logged in with.
 * The only class that reads core's own session keys.
 *
 * The current session is identified by the database id of its
 * authentication token, which is safe to store and show. The session id
 * itself is the token's secret: it is only handed on to be fingerprinted
 * or compared, never stored or shown.
 */
class CoreSession {
	/** Where core keeps the app password a session logged in with */
	private const APP_PASSWORD_KEY = 'app_password';
	/** Where core keeps the id of the token a request logged in with */
	private const TOKEN_ID_KEY = 'token-id';

	public function __construct(
		private readonly ISession $session,
		private readonly IProvider $tokenProvider,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * The PHP session id, or null without a session (occ, cron).
	 */
	public function sessionId(): ?string {
		try {
			$id = $this->session->getId();
		} catch (\Throwable) {
			return null;
		}
		return $id === '' ? null : $id;
	}

	/**
	 * The token id of the current session: the browser session's token, or
	 * the app password the request logged in with. Null without a session
	 * or when the session has no token. Looks the browser token up.
	 */
	public function tokenId(): ?int {
		$sessionId = $this->sessionId();
		if ($sessionId !== null) {
			try {
				return $this->tokenProvider->getToken($sessionId)->getId();
			} catch (\Throwable) {
				// No browser session token: the request may have logged in with an app password.
			}
		}
		return $this->loginTokenId();
	}

	/**
	 * The id of the token (app password or Bearer token) the request logged
	 * in with, as core keeps it in the session. No query.
	 */
	public function loginTokenId(): ?int {
		try {
			$id = $this->session->get(self::TOKEN_ID_KEY);
		} catch (\Throwable $e) {
			$this->logger->debug('Intrusion detection could not read the session token id', ['exception' => $e]);
			return null;
		}
		return is_int($id) || (is_string($id) && ctype_digit($id)) ? (int)$id : null;
	}

	/**
	 * The app password the session logged in with, to be compared only.
	 */
	public function appPassword(): ?string {
		try {
			$password = $this->session->get(self::APP_PASSWORD_KEY);
		} catch (\Throwable) {
			return null;
		}
		return is_string($password) && $password !== '' ? $password : null;
	}

	/**
	 * Whether the session logged in with an app password. A session that
	 * cannot be read counts as one: it proves no more than an app password.
	 */
	public function usesAppPassword(): bool {
		try {
			return $this->session->exists(self::APP_PASSWORD_KEY);
		} catch (\Throwable) {
			return true;
		}
	}
}
