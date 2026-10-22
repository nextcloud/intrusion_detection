<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Login;

use OCA\IntrusionDetection\Cache\Caches;
use OCP\ISession;

/**
 * Apps and WebDAV clients log in with every request. The gate lets the
 * first login per account, credential (an app password, or the password)
 * and address of each hour through to what records logins, the logins per
 * address ({@see \OCA\IntrusionDetection\Listener\LoginRecordListener}) and
 * the login history ({@see \OCA\IntrusionDetection\LoginHistory\LoginHistory}):
 *
 * - one atomic add in the memory cache decides for both; the answer is kept
 *   for the rest of the request;
 * - with a distributed cache, each web server also remembers the hour in its
 *   local cache, so that a busy client costs no distributed round trip after
 *   its first request of the hour on that server;
 * - without a memory cache it cannot tell, and the callers check the
 *   database (a read, never a write).
 */
class LoginGate {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'login';
	public const INTERVAL = 3600;
	/** Where core keeps the id of the token a request logged in with */
	private const TOKEN_ID_KEY = 'token-id';

	/** @var array<string, bool> by gate key */
	private array $answers = [];

	public function __construct(
		private readonly Caches $caches,
		private readonly ISession $session,
	) {
	}

	/**
	 * Whether this is the account's first login with the request's credential
	 * from the address in the hour; null without a memory cache.
	 */
	public function isFirst(string $uid, string $ipKey, int $now): ?bool {
		$tokenId = $this->tokenId();
		$key = hash('sha256', $uid . "\0" . ($tokenId === null ? 'password' : (string)$tokenId) . "\0" . $ipKey) . ':' . intdiv($now, self::INTERVAL);
		if (isset($this->answers[$key])) {
			return $this->answers[$key];
		}
		$shared = $this->caches->shared(self::CACHE);
		if ($shared === null) {
			return null;
		}
		$local = $this->caches->isDistributed() ? $this->caches->local(self::CACHE) : null;
		if ($local !== null && $local->get($key) !== null) {
			return $this->answers[$key] = false;
		}
		$first = $shared->add($key, 1, self::INTERVAL);
		$local?->set($key, 1, self::INTERVAL - $now % self::INTERVAL);
		return $this->answers[$key] = $first;
	}

	/**
	 * The id of the token (app password or Bearer token) the request logged
	 * in with, as core keeps it in the session.
	 */
	public function tokenId(): ?int {
		try {
			$id = $this->session->get(self::TOKEN_ID_KEY);
		} catch (\Throwable) {
			return null;
		}
		return is_int($id) || (is_string($id) && ctype_digit($id)) ? (int)$id : null;
	}

}
