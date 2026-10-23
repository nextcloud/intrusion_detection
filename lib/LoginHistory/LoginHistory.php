<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\LoginHistory;

use OCA\IntrusionDetection\Config\PurgeRetention;
use OCA\IntrusionDetection\Db\IPurges;
use OCA\IntrusionDetection\Db\KeyMatch;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Login\LoginKind;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Login\SessionTokenLinker;
use OCA\IntrusionDetection\LoginHistory\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Response\IAcceptedLogins;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * The login history (concept section 7, `ids_login_history`): one row per
 * successful login, with the address, the client, how the account logged
 * in and how the login was confirmed. It feeds the personal security page,
 * the incident report and the account takeover check.
 *
 * - A login costs one insert. Its step-up outcome is known by then: the
 *   login's step-up step runs first and hands its decision on. A
 *   confirmation that follows later on the verify page updates the row.
 * - Apps that send a password or an app password with every request would
 *   write a row per request, so these logins are written at most once per
 *   credential (the app password, or the password), network and
 *   HISTORY_INTERVAL, with or without a memory cache: a client that stays
 *   on one network is one row a day. The {@see \OCA\IntrusionDetection\Login\LoginGate} lets one login
 *   per credential, address and hour through to the indexed check.
 * - Browser sessions get their session token linked on their first request
 *   ({@see SessionTokenLinker}), since core creates the token after the
 *   login event. The session marker
 *   goes then, so that later requests have nothing to check; later updates
 *   of the row find it by the session's token.
 *
 * Never a password, token or session id: only the token's database id.
 */
class LoginHistory implements IAcceptedLogins, IPurges {
	/** The login form */
	public const METHOD_PASSWORD = 'password';
	/** An app or script sending the account's password (Basic auth) */
	public const METHOD_CLIENT_PASSWORD = 'client_password';
	/** An app password (Basic auth) */
	public const METHOD_APP_PASSWORD = 'app_password';
	/** A token in an Authorization: Bearer header */
	public const METHOD_TOKEN = 'token';
	/** The remember-me cookie of a browser */
	public const METHOD_COOKIE = 'cookie';
	/** Single sign-on and other logins without a password */
	public const METHOD_SSO = 'sso';
	public const METHODS = [self::METHOD_PASSWORD, self::METHOD_CLIENT_PASSWORD, self::METHOD_APP_PASSWORD, self::METHOD_TOKEN, self::METHOD_COOKIE, self::METHOD_SSO];

	public const CONFIRMED_BY_NONE = 'none';
	public const CONFIRMED_BY = ['none', 'second_factor', 'email_code', 'known_device', 'admin_approval'];

	public const STEP_UP_PENDING = 'pending';
	public const STEP_UP_CONFIRMED = 'confirmed';
	/** Allowed without a confirmation, as the policy says */
	public const STEP_UP_ALLOWED = 'allowed';
	public const STEP_UP_REFUSED = 'refused';
	/** Not confirmed in time, wrong codes, rejected by an administrator, or given up */
	public const STEP_UP_FAILED = 'failed';
	public const STEP_UP = [self::STEP_UP_PENDING, self::STEP_UP_CONFIRMED, self::STEP_UP_ALLOWED, self::STEP_UP_REFUSED, self::STEP_UP_FAILED];

	/** An app's logins with one credential from one network are one row this long */
	public const HISTORY_INTERVAL = 86400;
	/** A session's own login is looked up this far back by its token */
	private const SESSION_LOOKBACK = 86400;

	public function __construct(
		private readonly LoginHistoryMapper $mapper,
		private readonly SessionMarkers $state,
		private readonly CoreSession $coreSession,
		private readonly SessionTokenLinker $linker,
		private readonly ITimeFactory $timeFactory,
		private readonly PurgeRetention $retention,
	) {
	}

	/**
	 * The method a kind of login is recorded with, or null for a browser
	 * session restored from its token, which is no new login.
	 *
	 * @return ?self::METHOD_*
	 */
	public static function methodOf(LoginKind $kind): ?string {
		return match ($kind) {
			LoginKind::FormPassword => self::METHOD_PASSWORD,
			LoginKind::ClientPassword => self::METHOD_CLIENT_PASSWORD,
			LoginKind::OtherPassword, LoginKind::Sso => self::METHOD_SSO,
			LoginKind::AppPasswordBasic => self::METHOD_APP_PASSWORD,
			LoginKind::Bearer => self::METHOD_TOKEN,
			LoginKind::RememberMeCookie => self::METHOD_COOKIE,
			LoginKind::RestoredSession => null,
		};
	}

	/**
	 * Delete the logins past the retention setting of the detections.
	 */
	#[\Override]
	public function purge(int $now): int {
		return $this->mapper->deleteOlderThan($now - $this->retention->days($now) * 86400);
	}

	/**
	 * Record a successful login.
	 *
	 * @param self::METHOD_* $method
	 * @param bool $knownDevice whether it came from a device the account remembered
	 * @param bool $browser a browser session, whose session token is linked on its first request
	 * @param string $confirmedBy how the login was confirmed ({@see self::CONFIRMED_BY})
	 * @param ?self::STEP_UP_* $stepUp the step-up's outcome at login, null when nothing was needed
	 * @param ?bool $firstOfTheHour the {@see \OCA\IntrusionDetection\Login\LoginGate}'s answer for an app; null when it cannot tell
	 * @return ?int the new row, or null when the login was recorded recently
	 */
	public function record(string $uid, string $method, ?SourceKey $source, ?string $userAgent, bool $knownDevice, bool $browser, string $confirmedBy = self::CONFIRMED_BY_NONE, ?string $stepUp = null, ?bool $firstOfTheHour = null): ?int {
		$now = $this->timeFactory->getTime();
		$tokenId = $browser ? null : $this->coreSession->loginTokenId();
		if (!$browser && ($firstOfTheHour === false || $this->mapper->existsSince($uid, $method, $tokenId, $source?->netKey, $now - self::HISTORY_INTERVAL))) {
			return null;
		}
		$id = $this->mapper->insert(
			$uid,
			$now,
			$source,
			UserMessages::shortUserAgent($userAgent),
			$method,
			$knownDevice,
			$confirmedBy,
			$stepUp,
			$tokenId,
		);
		if ($browser) {
			$this->state->set(SessionMarkers::LOGIN_HISTORY, ['uid' => $uid, 'id' => $id, 'linked' => false]);
		}
		return $id;
	}

	/**
	 * The login of the current session was confirmed, or not, after the
	 * login itself (on the verify page).
	 *
	 * @param self::STEP_UP_CONFIRMED|self::STEP_UP_FAILED $stepUp
	 */
	public function outcome(string $uid, string $confirmedBy, string $stepUp): void {
		$id = $this->rowOf($uid);
		if ($id !== null) {
			$this->mapper->setOutcome($id, $uid, $confirmedBy, $stepUp);
		}
	}

	/**
	 * The login of the current session passed core's second factor.
	 */
	public function secondFactorPassed(string $uid): void {
		$id = $this->rowOf($uid);
		if ($id !== null) {
			$this->mapper->setSecondFactor($id, $uid);
		}
	}

	/**
	 * Link the current session's token to its login, once, and drop the
	 * session marker.
	 */
	public function linkSession(?string $currentUid): void {
		$this->linker->link(SessionMarkers::LOGIN_HISTORY, $currentUid, function (array $marker, int $tokenId): void {
			if (is_int($marker['id'] ?? null)) {
				$this->mapper->setSessionToken($marker['id'], (string)$marker['uid'], $tokenId);
			}
		});
	}

	/**
	 * @return list<LoginHistoryEntry> the account's logins in [since, until), newest first unless `$oldestFirst`
	 */
	public function forUser(string $uid, int $since, ?int $until = null, int $limit = 100, bool $oldestFirst = false): array {
		return $this->mapper->forUser($uid, $since, $until, $limit, $oldestFirst);
	}

	/**
	 * The logins from one address, or from a network when given its key
	 * (as in {@see SourceKey::$netKey}), in [since, until), newest first
	 * unless `$oldestFirst`.
	 *
	 * @return list<LoginHistoryEntry>
	 */
	public function forAddress(string $address, int $since, ?int $until = null, int $limit = 100, bool $oldestFirst = false): array {
		return $this->mapper->forAddress($address, $since, $until, $limit, $oldestFirst);
	}

	/**
	 * The newest login of an account that started a session (or app
	 * password) token.
	 */
	public function forSession(string $uid, int $sessionTokenId): ?LoginHistoryEntry {
		return $this->mapper->forSession($uid, $sessionTokenId);
	}

	/**
	 * Whether the account logged in from this network (as in
	 * {@see SourceKey::$netKey}) since a time with a login that went
	 * through: it needed nothing, or it was confirmed.
	 */
	public function wentThroughFrom(string $uid, string $netKey, int $since): bool {
		return $this->mapper->wentThroughFrom($uid, $netKey, $since);
	}

	/**
	 * A login that waited for its confirmation since `$started` failed
	 * (it was left waiting past its deadline).
	 *
	 * @return ?LoginHistoryEntry its row, or null when none waits
	 */
	public function failPending(string $uid, int $started): ?LoginHistoryEntry {
		$entry = $this->mapper->stepUpAround($uid, $started, self::STEP_UP_PENDING);
		if ($entry !== null) {
			$this->mapper->setOutcome($entry->id, $uid, self::CONFIRMED_BY_NONE, self::STEP_UP_FAILED);
		}
		return $entry;
	}

	/**
	 * The row of a refused login that started at `$started`, or null.
	 */
	public function refusedAround(string $uid, int $started): ?LoginHistoryEntry {
		return $this->mapper->stepUpAround($uid, $started, self::STEP_UP_REFUSED);
	}

	#[\Override]
	public function acceptedUidsFrom(string $column, KeyMatch $keys, int $since, int $limit): array {
		return $this->mapper->acceptedUidsFrom($column, $keys, $since, $limit);
	}

	#[\Override]
	public function hasConfirmedLogin(string $uid, string $column, KeyMatch $keys, int $since): bool {
		return $this->mapper->hasConfirmedLogin($uid, $column, $keys, $since);
	}

	/**
	 * The row of the current session's login: from the session marker until
	 * it is linked, then by the session's token.
	 */
	private function rowOf(string $uid): ?int {
		$marker = $this->state->get(SessionMarkers::LOGIN_HISTORY);
		if ($marker !== null) {
			return ($marker['uid'] ?? null) === $uid && is_int($marker['id'] ?? null) ? $marker['id'] : null;
		}
		$tokenId = $this->coreSession->tokenId();
		return $tokenId === null ? null : $this->mapper->idForSessionToken($uid, $tokenId, $this->timeFactory->getTime() - self::SESSION_LOOKBACK);
	}
}
