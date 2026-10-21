<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\LoginHistory;

use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\KnownDevice\KnownDevice;
use OCA\IntrusionDetection\Login\LoginGate;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * The login history (concept section 7, `ids_login_history`): one row per
 * successful login, with the address, the client, how the account logged
 * in and how the login was confirmed. It feeds the personal security page,
 * the incident report and the account takeover check.
 *
 * - A login costs one insert. Its step-up outcome is known by then, because
 *   the step-up listener runs first; a confirmation that follows later on
 *   the verify page updates the row.
 * - Apps that send a password or an app password with every request would
 *   write a row per request, so these logins are written at most once per
 *   credential (the app password, or the password), network and
 *   HISTORY_INTERVAL, with or without a memory cache: a client that stays
 *   on one network is one row a day. The {@see LoginGate} lets one login
 *   per credential, address and hour through to the indexed check.
 * - Browser sessions get their session token linked on their first request
 *   ({@see \OCA\IntrusionDetection\SessionState\Rules\LoginHistoryRule}),
 *   since core creates the token after the login event.
 *
 * Never a password, token or session id: only the token's database id.
 */
class LoginHistory {
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
	/** A confirmation recorded this recently belongs to the login being recorded */
	private const CONFIRMATION_AGE = 60;

	public function __construct(
		private readonly LoginHistoryMapper $mapper,
		private readonly SessionState $state,
		private readonly CurrentSession $currentSession,
		private readonly LoginGate $gate,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * Record a successful login.
	 *
	 * @param self::METHOD_* $method
	 * @param bool $browser a browser session, whose session token is linked on its first request
	 * @return ?int the new row, or null when the login was recorded recently
	 */
	public function record(string $uid, string $method, ?SourceKey $source, ?string $userAgent, ?KnownDevice $device, bool $browser): ?int {
		$now = $this->timeFactory->getTime();
		$tokenId = $browser ? null : $this->gate->tokenId();
		if (!$browser && !$this->passesGate($uid, $method, $tokenId, $source, $now)) {
			return null;
		}
		[$confirmedBy, $stepUp] = $this->outcomeAtLogin($uid, $now);
		$id = $this->mapper->insert(
			$uid,
			$now,
			$source,
			UserMessages::shortUserAgent($userAgent),
			$method,
			$device !== null,
			$confirmedBy,
			$stepUp,
			$tokenId,
		);
		if ($browser) {
			$this->state->set(SessionState::LOGIN_HISTORY, ['uid' => $uid, 'id' => $id, 'linked' => false]);
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
	 * Link the current session's token to its login, once.
	 *
	 * @param array<string, mixed> $marker
	 */
	public function link(array $marker, ?string $currentUid): void {
		$uid = $marker['uid'] ?? null;
		$id = $marker['id'] ?? null;
		if (!is_string($uid) || !is_int($id) || $uid !== $currentUid) {
			$this->state->remove(SessionState::LOGIN_HISTORY);
			return;
		}
		$tokenId = $this->currentSession->tokenId();
		if ($tokenId !== null) {
			$this->mapper->setSessionToken($id, $uid, $tokenId);
		}
		$this->state->set(SessionState::LOGIN_HISTORY, ['uid' => $uid, 'id' => $id, 'linked' => true]);
	}

	private function rowOf(string $uid): ?int {
		$marker = $this->state->get(SessionState::LOGIN_HISTORY);
		return $marker !== null && ($marker['uid'] ?? null) === $uid && is_int($marker['id'] ?? null) ? $marker['id'] : null;
	}

	/**
	 * How the login being recorded was confirmed, from what the step-up
	 * decided just before.
	 *
	 * @return array{0: string, 1: ?string}
	 */
	private function outcomeAtLogin(string $uid, int $now): array {
		$stepUp = StepUpState::fromArray($this->state->get(SessionState::STEP_UP) ?? []);
		if ($stepUp !== null && $stepUp->uid === $uid) {
			return [self::CONFIRMED_BY_NONE, match ($stepUp->status) {
				StepUpState::PENDING => self::STEP_UP_PENDING,
				StepUpState::RESUMED => self::STEP_UP_FAILED,
				default => self::STEP_UP_REFUSED,
			}];
		}
		$confirmation = $this->state->get(SessionState::CONFIRMATION);
		if ($confirmation !== null && ($confirmation['uid'] ?? null) === $uid && is_int($confirmation['at'] ?? null) && $confirmation['at'] >= $now - self::CONFIRMATION_AGE) {
			$by = is_string($confirmation['by'] ?? null) && in_array($confirmation['by'], self::CONFIRMED_BY, true) ? $confirmation['by'] : self::CONFIRMED_BY_NONE;
			return [$by, $by === self::CONFIRMED_BY_NONE ? self::STEP_UP_ALLOWED : self::STEP_UP_CONFIRMED];
		}
		return [self::CONFIRMED_BY_NONE, null];
	}

	/**
	 * Whether a login of an app is due for a row: the first with its
	 * credential from its network in HISTORY_INTERVAL.
	 */
	private function passesGate(string $uid, string $method, ?int $tokenId, ?SourceKey $source, int $now): bool {
		if ($source !== null && $this->gate->isFirst($uid, $source->ipKey, $now) === false) {
			return false;
		}
		return !$this->mapper->existsSince($uid, $method, $tokenId, $source?->netKey, $now - self::HISTORY_INTERVAL);
	}
}
