<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState;

use OCP\Authentication\Token\IProvider;
use OCP\ISession;
use Psr\Log\LoggerInterface;

/**
 * Identifies the current request's session by the database id of its
 * authentication token, which is safe to store and show. The session id
 * itself is the token's secret and never leaves this class.
 */
class CurrentSession {
	/** Where core keeps the id of the token a session logged in with */
	private const TOKEN_ID_KEY = 'token-id';

	public function __construct(
		private readonly ISession $session,
		private readonly IProvider $tokenProvider,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * The token id of the current session: the browser session's token, or
	 * the app password the request logged in with. Null without a session
	 * (occ, cron) or when the session has no token.
	 */
	public function tokenId(): ?int {
		try {
			return $this->tokenProvider->getToken($this->session->getId())->getId();
		} catch (\Throwable) {
			// No browser session token: the request may have logged in with an app password.
		}
		try {
			$id = $this->session->get(self::TOKEN_ID_KEY);
			return is_int($id) || (is_string($id) && ctype_digit($id)) ? (int)$id : null;
		} catch (\Throwable $e) {
			$this->logger->debug('Intrusion detection could not read the session token id', ['exception' => $e]);
			return null;
		}
	}
}
