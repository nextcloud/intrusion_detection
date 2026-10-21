<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused;
use OCA\IntrusionDetection\Check\Checks\StepUpRefusedClient;
use OCA\IntrusionDetection\Check\Checks\StepUpUnconfirmed;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserSession;
use Psr\Log\LoggerInterface;

/**
 * Extra confirmation of password logins (concept section 11.5).
 *
 * At a login with reasons ({@see StepUpReasons}), the confirmation methods
 * ({@see ConfirmationPolicy}) are tried in order:
 *
 * - The account's second factor: core's challenge right after the password.
 *   The login waits until the challenge is passed.
 * - A method that needs the user (an email code): the session is marked,
 *   and {@see \OCA\IntrusionDetection\SessionState\Rules\StepUpRule} sends
 *   every request to the verify page until it is confirmed, fails, or
 *   `step_up_session_ttl` has passed.
 * - No method: the policies decide ({@see ConfirmationPolicy::noMethodDecision()}):
 *   the login is refused, or allowed with a notice or a new password.
 *
 * Apps and scripts that send the password (Basic auth) cannot answer a
 * confirmation, so their request is refused unless the policies allow
 * logins that nothing confirms.
 *
 * How a login was confirmed is kept in the session ({@see SessionState::CONFIRMATION}:
 * none, second_factor, known_device, email_code, admin_approval), for later
 * decisions about the session, and in the login history.
 * Unconfirmed sessions are also remembered on the server
 * ({@see UnconfirmedSessions}), so that they cannot come back without
 * their state.
 */
class StepUpService {
	public const NONE = 'none';
	public const CONFIRMED = 'confirmed';
	public const PENDING = 'pending';
	public const REFUSED = 'refused';
	public const REFUSED_CLIENT = 'refused_client';
	public const ALLOWED = 'allowed';
	/** Outcomes of apps sending the password that may be repeated ({@see self::repeatClient()}) */
	public const REPEATABLE = [self::NONE, self::REFUSED_CLIENT, self::ALLOWED];

	/** confirmed_by of a login that was allowed without a confirmation */
	public const CONFIRMED_BY_NONE = 'none';
	/** Core creates a session token for a Basic auth login only when the client sends this cookie */
	public const COOKIE_TEST = 'cookie_test';

	public function __construct(
		private readonly SessionState $state,
		private readonly ISession $session,
		private readonly IUserSession $userSession,
		private readonly ConfirmationPolicy $policy,
		private readonly ResponseEngine $engine,
		private readonly Settings $settings,
		private readonly UnconfirmedSessions $unconfirmed,
		private readonly CurrentSession $currentSession,
		private readonly RemoteAddressResolver $addresses,
		private readonly StepUpFailed $failedCheck,
		private readonly StepUpUnconfirmed $unconfirmedCheck,
		private readonly ITimeFactory $timeFactory,
		private readonly AuditLogger $audit,
		private readonly LoggerInterface $logger,
		private readonly LoginHistory $history,
		private readonly FamiliarLogin $familiar,
		private readonly IRequest $request,
	) {
	}

	/**
	 * Decide a successful password login with these reasons.
	 *
	 * @param list<StepUpPolicy> $policies
	 * @return array{0: self::NONE|self::CONFIRMED|self::PENDING|self::REFUSED|self::REFUSED_CLIENT|self::ALLOWED, 1: list<int>} what happened, and the detections it recorded
	 */
	public function atLogin(LoginContext $login, array $policies): array {
		if ($policies === []) {
			return [self::NONE, []];
		}
		$uid = $login->uid();
		$now = $this->timeFactory->getTime();
		$policyIds = array_map(static fn (StepUpPolicy $p): string => $p->value, $policies);

		if (!$login->interactive) {
			$decision = $this->policy->noMethodDecision($policies, fn (): bool => $this->familiar->isFamiliar($login));
			if (!$decision->refuse) {
				return $this->allow($login, $policyIds, $decision);
			}
			$detection = $this->record(new DetectionDraft(
				checkId: StepUpRefusedClient::ID,
				source: $login->source,
				uid: $uid,
				facts: ['policies' => $policyIds],
				merge: DetectionDraft::MERGE_SOURCE_USER,
				mergeWindow: 86400,
				userAgent: $login->userAgent,
			));
			// Without the cookie, core gives the client no session token: nothing could resume this session.
			$resumable = $this->request->getCookie(self::COOKIE_TEST) !== null;
			$this->mark(new StepUpState($uid, StepUpState::REFUSED_CLIENT, $policyIds, $now, 0, $login->source?->ip, detectionId: $detection?->getId()), $resumable);
			return [self::REFUSED_CLIENT, self::ids($detection)];
		}

		$methods = $this->policy->methodsForAll($login->user, $policies);
		$state = new StepUpState($uid, StepUpState::PENDING, $policyIds, $now, $now + $this->settings->getInt(GlobalSettings::STEP_UP_SESSION_TTL), $login->source?->ip);
		foreach ($methods as $i => $method) {
			$state->methods = array_map(static fn (IConfirmationMethod $m): string => $m->id(), array_slice($methods, $i));
			$started = $method->begin($login->user, $state);
			if ($started === IConfirmationMethod::CONFIRMED) {
				$this->confirmation($uid, $method->id(), $policyIds);
				return [self::CONFIRMED, []];
			}
			if ($started === IConfirmationMethod::PENDING) {
				$this->mark($state);
				$this->audit->log('login of %s needs extra confirmation (%s), with %s', ['uid' => $uid, 'reasons' => implode(', ', $policyIds), 'method' => $method->id()]);
				return [self::PENDING, []];
			}
		}

		$decision = $this->policy->noMethodDecision($policies, fn (): bool => $this->familiar->isFamiliar($login));
		if (!$decision->refuse) {
			return $this->allow($login, $policyIds, $decision);
		}
		$detection = $this->record(new DetectionDraft(
			checkId: StepUpRefused::ID,
			source: $login->source,
			uid: $uid,
			facts: ['policies' => $policyIds],
			merge: DetectionDraft::MERGE_SOURCE_USER,
			userAgent: $login->userAgent,
		));
		$this->mark(new StepUpState(
			$uid,
			StepUpState::REFUSED,
			$policyIds,
			$now,
			0,
			$login->source?->ip,
			reference: $detection === null ? null : StepUpReference::of($detection->getId()),
			detectionId: $detection?->getId(),
		));
		$this->audit->log('login of %s refused: it needed extra confirmation (%s), and nothing could confirm it', ['uid' => $uid, 'reasons' => implode(', ', $policyIds)]);
		return [self::REFUSED, self::ids($detection)];
	}

	/**
	 * Repeat a decision about an app sending the password, made moments
	 * ago for the same account, password and address, without recording
	 * it again.
	 *
	 * @param self::NONE|self::REFUSED_CLIENT|self::ALLOWED $outcome
	 * @param list<string> $policyIds
	 */
	public function repeatClient(string $uid, ?SourceKey $source, string $outcome, array $policyIds): void {
		if ($outcome === self::REFUSED_CLIENT) {
			$now = $this->timeFactory->getTime();
			$this->mark(new StepUpState($uid, StepUpState::REFUSED_CLIENT, $policyIds, $now, 0, $source?->ip), $this->request->getCookie(self::COOKIE_TEST) !== null);
		} elseif ($outcome === self::ALLOWED) {
			$this->confirmation($uid, self::CONFIRMED_BY_NONE, $policyIds);
		}
	}

	/**
	 * The step-up of the current session, if any.
	 */
	public function current(): ?StepUpState {
		$data = $this->state->get(SessionState::STEP_UP);
		return $data === null ? null : StepUpState::fromArray($data);
	}

	public function save(StepUpState $stepUp): bool {
		return $this->state->set(SessionState::STEP_UP, $stepUp->toArray());
	}

	/**
	 * The login was confirmed: the session may continue.
	 */
	public function complete(StepUpState $stepUp, string $method): void {
		$this->state->remove(SessionState::STEP_UP);
		$this->confirmation($stepUp->uid, $method, $stepUp->policies);
		$this->unconfirmed->forget($this->sessionId());
		$this->recordOutcome($stepUp->uid, $method, LoginHistory::STEP_UP_CONFIRMED);
		$this->audit->log('login of %s confirmed with %s', ['uid' => $stepUp->uid, 'method' => $method]);
	}

	/**
	 * The user gave up a login that waits for its confirmation: it ends
	 * without a detection, since nothing points to an attack.
	 */
	public function abandon(StepUpState $stepUp): void {
		$this->recordOutcome($stepUp->uid, LoginHistory::CONFIRMED_BY_NONE, LoginHistory::STEP_UP_FAILED);
		$this->unconfirmed->forget($this->sessionId());
		$this->state->remove(SessionState::STEP_UP);
		if ($this->userSession->isLoggedIn()) {
			$this->userSession->logout();
		}
		$this->audit->log('login of %s given up while it waited for its confirmation', ['uid' => $stepUp->uid]);
	}

	/**
	 * The login was not confirmed: record `step_up_failed`, which ends the
	 * session with its responses, and end it in any case.
	 *
	 * @param StepUpFailed::RULE_* $rule
	 */
	public function fail(StepUpState $stepUp, string $rule): ?Detection {
		$sessionId = $this->sessionId();
		$sessionTokenId = $this->currentSession->tokenId();
		$source = $this->addresses->current() ?? ($stepUp->ip === null ? null : SourceKey::tryFromIp($stepUp->ip));
		$draft = new DetectionDraft(
			checkId: StepUpFailed::ID,
			source: $source,
			uid: $stepUp->uid,
			facts: [
				'rule' => $rule,
				'policies' => $stepUp->policies,
				'attempts' => $stepUp->attempts,
				'started' => $stepUp->started,
				'ttl' => $this->settings->getInt(GlobalSettings::STEP_UP_SESSION_TTL),
				'sessionTokenId' => $sessionTokenId,
			],
			merge: DetectionDraft::MERGE_SOURCE_USER,
			sessionTokenId: $sessionTokenId,
		);
		// Before the responses, which may end the session and its markers with it.
		$this->recordOutcome($stepUp->uid, LoginHistory::CONFIRMED_BY_NONE, LoginHistory::STEP_UP_FAILED);
		$detection = $this->record($draft, $this->failedCheck->responsesFor($draft, $this->settings->responses(StepUpFailed::ID), []));
		$this->unconfirmed->forget($sessionId);
		if ($this->userSession->isLoggedIn()) {
			$this->state->remove(SessionState::STEP_UP);
			$this->userSession->logout();
		}
		$this->audit->log('login of %s ended: not confirmed (%s)', ['uid' => $stepUp->uid, 'rule' => $rule]);
		return $detection;
	}

	/**
	 * End a refused login after it was shown why.
	 */
	public function endRefused(): void {
		$this->unconfirmed->forget($this->sessionId());
		if ($this->userSession->isLoggedIn()) {
			$this->userSession->logout();
		}
	}

	/**
	 * A session whose login was never confirmed came back through its
	 * remember-me cookie or its session token, without its step-up state.
	 * Mark it so that the session rule ends it on its first request.
	 *
	 * @param ?string $previousSessionId the session id it came back from, when core gave it a new one
	 */
	public function resumed(string $uid, ?string $previousSessionId = null): void {
		if ($previousSessionId !== null) {
			$this->unconfirmed->forget($previousSessionId);
		}
		$now = $this->timeFactory->getTime();
		$this->mark(new StepUpState($uid, StepUpState::RESUMED, [], $now, $now, $this->addresses->current()?->ip));
		$this->audit->log('a session of %s whose login was never confirmed came back and is ended', ['uid' => $uid]);
	}

	/**
	 * Allowed without a method: record it, with the responses the policies
	 * ask for (tell the user and the administrators, require a new password).
	 *
	 * @param list<string> $policyIds
	 * @return array{0: self::ALLOWED, 1: list<int>}
	 */
	private function allow(LoginContext $login, array $policyIds, NoMethodDecision $decision): array {
		$draft = new DetectionDraft(
			checkId: StepUpUnconfirmed::ID,
			source: $login->source,
			uid: $login->uid(),
			facts: ['policies' => $policyIds, 'client' => !$login->interactive, 'notify' => $decision->notify, 'forceChange' => $decision->forceChange],
			merge: DetectionDraft::MERGE_SOURCE_USER,
			userAgent: $login->userAgent,
		);
		$detection = $this->record($draft, $this->unconfirmedCheck->responsesFor($draft, $this->settings->responses(StepUpUnconfirmed::ID), []));
		$this->confirmation($login->uid(), self::CONFIRMED_BY_NONE, $policyIds);
		$this->audit->log('login of %s allowed without confirmation (%s)', ['uid' => $login->uid(), 'reasons' => implode(', ', $policyIds)]);
		return [self::ALLOWED, self::ids($detection)];
	}

	/**
	 * Record a detection and run its responses. A failure is logged: the
	 * decision about the login stands without its detection.
	 *
	 * @param list<ResponseType>|null $responses
	 */
	private function record(DetectionDraft $draft, ?array $responses = null): ?Detection {
		try {
			return $this->engine->handle($draft, $responses);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not record {check}', ['check' => $draft->checkId, 'exception' => $e]);
			return null;
		}
	}

	/**
	 * @param LoginHistory::STEP_UP_CONFIRMED|LoginHistory::STEP_UP_FAILED $outcome
	 */
	private function recordOutcome(string $uid, string $confirmedBy, string $outcome): void {
		try {
			$this->history->outcome($uid, $confirmedBy, $outcome);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not update the login history', ['exception' => $e]);
		}
	}

	/**
	 * @param bool $resumable whether the session could come back without its state, and must be remembered
	 */
	private function mark(StepUpState $stepUp, bool $resumable = true): void {
		if (!$this->save($stepUp)) {
			// Without a writable session the login cannot be held back; the error is logged by the session state.
			return;
		}
		$sessionId = $this->sessionId();
		if ($resumable && $sessionId !== '') {
			$this->unconfirmed->remember($sessionId, $stepUp->uid);
		}
	}

	/**
	 * @param list<string> $policyIds
	 */
	private function confirmation(string $uid, string $method, array $policyIds): void {
		$this->state->set(SessionState::CONFIRMATION, [
			'uid' => $uid,
			'by' => $method,
			'policies' => $policyIds,
			'at' => $this->timeFactory->getTime(),
		]);
	}

	private function sessionId(): string {
		try {
			return $this->session->getId();
		} catch (\Throwable) {
			return '';
		}
	}

	/**
	 * @return list<int>
	 */
	private static function ids(?Detection $detection): array {
		return $detection === null ? [] : [$detection->getId()];
	}
}
