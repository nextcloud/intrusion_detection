<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailed;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailedFacts;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailedRule;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused\StepUpRefused;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused\StepUpRefusedFacts;
use OCA\IntrusionDetection\Check\Checks\StepUpRefusedClient\StepUpRefusedClient;
use OCA\IntrusionDetection\Check\Checks\StepUpRefusedClient\StepUpRefusedClientFacts;
use OCA\IntrusionDetection\Check\Checks\StepUpUnconfirmed\StepUpUnconfirmed;
use OCA\IntrusionDetection\Check\Checks\StepUpUnconfirmed\StepUpUnconfirmedFacts;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Login\LoginContext;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IRequest;
use OCP\IUserSession;
use Psr\Log\LoggerInterface;

/**
 * Extra confirmation of password logins (concept section 11.5): the one
 * writer of a login's confirmation. Every change of a login's
 * {@see LoginConfirmation} happens here, is kept in the
 * {@see LoginConfirmationStore}, and updates the login history.
 *
 * At a login with reasons ({@see StepUpReasons}), the confirmation methods
 * ({@see ConfirmationPolicy}) are tried in order:
 *
 * - The account's second factor: core's challenge right after the password.
 *   The login waits until the challenge is passed.
 * - A method that needs the user (an email code): the session is marked,
 *   and {@see \OCA\IntrusionDetection\SessionState\Rules\StepUpRule} sends
 *   every request to the verify page until it is confirmed, fails, or
 *   SESSION_TTL has passed.
 * - No method: the policies decide ({@see ConfirmationPolicy::noMethodDecision()}):
 *   the login is refused, or allowed with a notice or a new password.
 *
 * Apps and scripts that send the password (Basic auth) cannot answer a
 * confirmation, and none is ever started for them, whatever cookies they
 * send. When the account could confirm the login in a browser
 * ({@see ConfirmationPolicy::canConfirmInBrowser()}), they are refused and
 * pointed to app passwords, except from a familiar place ({@see FamiliarLogin})
 * while every reason allows that ({@see StepUpPolicy::allowsFamiliarApps()}):
 * then, as for accounts without any method, the policies decide.
 *
 * From pending, a login is confirmed (complete()), fails (fail(), also for
 * a login left waiting past its deadline: abandoned()), or is given up
 * (abandon()). A refused login ends once it was told why (endRefused()). A
 * session whose login was never confirmed and that comes back without its
 * state is marked resumed, and fails on its next request.
 */
class LoginConfirmations {
	/** Seconds a login may wait for its confirmation before it is ended */
	public const SESSION_TTL = 900;
	/** Core creates a session token for a Basic auth login only when the client sends this cookie */
	public const COOKIE_TEST = 'cookie_test';

	public function __construct(
		private readonly LoginConfirmationStore $store,
		private readonly IUserSession $userSession,
		private readonly ConfirmationPolicy $policy,
		private readonly ResponseEngine $engine,
		private readonly CoreSession $coreSession,
		private readonly RemoteAddressResolver $addresses,
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
	 * @return array{0: LoginConfirmation, 1: list<int>} the decision, and the detections it recorded
	 */
	public function atLogin(LoginContext $login, array $policies): array {
		if ($policies === []) {
			return [LoginConfirmation::none($login->uid()), []];
		}
		$uid = $login->uid();
		$now = $this->timeFactory->getTime();
		$policyIds = array_map(static fn (StepUpPolicy $p): string => $p->value, $policies);
		$familiar = null;
		$isFamiliar = function () use (&$familiar, $login): bool {
			return $familiar ??= $this->familiar->isFamiliar($login);
		};

		if (!$login->interactive) {
			$inBrowser = $this->policy->canConfirmInBrowser($login->user, $policies);
			if (!$inBrowser || (self::allowFamiliarApps($policies) && $isFamiliar())) {
				$decision = $this->policy->noMethodDecision($policies, $isFamiliar);
				if (!$decision->refuse) {
					return $this->allow($login, $policyIds, $decision);
				}
			}
			$detection = $this->record(new DetectionDraft(
				checkId: StepUpRefusedClient::ID,
				source: $login->source,
				uid: $uid,
				facts: new StepUpRefusedClientFacts($policyIds, $inBrowser),
				merge: DetectionDraft::MERGE_SOURCE_USER,
				mergeWindow: 86400,
				userAgent: $login->userAgent,
			));
			$refused = new StepUpState($uid, ConfirmationStatus::RefusedClient, $policyIds, $now, 0, $login->source?->ip, detectionId: $detection?->getId());
			return [$this->store->put(LoginConfirmation::ofStepUp($refused), $this->clientResumable()), self::ids($detection)];
		}

		$methods = $this->policy->methodsForAll($login->user, $policies);
		$state = new StepUpState($uid, ConfirmationStatus::Pending, $policyIds, $now, $now + self::SESSION_TTL, $login->source?->ip);
		foreach ($methods as $i => $method) {
			$start = $method->begin($login->user, $state->withMethods(array_map(static fn (IConfirmationMethod $m): string => $m->id(), array_slice($methods, $i))));
			$state = $start->state;
			if ($start->outcome === IConfirmationMethod::CONFIRMED) {
				return [$this->store->put(LoginConfirmation::confirmed($uid, $method->id(), $policyIds, $now)), []];
			}
			if ($start->outcome === IConfirmationMethod::PENDING) {
				$pending = $this->store->put(LoginConfirmation::ofStepUp($state));
				$this->audit->log('login of %s needs extra confirmation (%s), with %s', ['uid' => $uid, 'reasons' => implode(', ', $policyIds), 'method' => $method->id()]);
				return [$pending, []];
			}
		}

		$decision = $this->policy->noMethodDecision($policies, $isFamiliar);
		if (!$decision->refuse) {
			return $this->allow($login, $policyIds, $decision);
		}
		$detection = $this->record(new DetectionDraft(
			checkId: StepUpRefused::ID,
			source: $login->source,
			uid: $uid,
			facts: new StepUpRefusedFacts($policyIds),
			merge: DetectionDraft::MERGE_SOURCE_USER,
			userAgent: $login->userAgent,
		));
		$refused = $this->store->put(LoginConfirmation::ofStepUp(new StepUpState(
			$uid,
			ConfirmationStatus::Refused,
			$policyIds,
			$now,
			0,
			$login->source?->ip,
			reference: $detection === null ? null : StepUpReference::of($detection->getId()),
			detectionId: $detection?->getId(),
		)));
		$this->audit->log('login of %s refused: it needed extra confirmation (%s), and nothing could confirm it', ['uid' => $uid, 'reasons' => implode(', ', $policyIds)]);
		return [$refused, self::ids($detection)];
	}

	/**
	 * Repeat a decision about an app sending the password, made moments
	 * ago for the same account, password and address, without recording
	 * it again.
	 *
	 * @param ConfirmationStatus::None|ConfirmationStatus::RefusedClient|ConfirmationStatus::AllowedUnconfirmed $outcome
	 * @param list<string> $policyIds
	 */
	public function repeatClient(string $uid, ?SourceKey $source, ConfirmationStatus $outcome, array $policyIds): LoginConfirmation {
		$now = $this->timeFactory->getTime();
		return match ($outcome) {
			ConfirmationStatus::RefusedClient => $this->store->put(LoginConfirmation::ofStepUp(new StepUpState($uid, ConfirmationStatus::RefusedClient, $policyIds, $now, 0, $source?->ip)), $this->clientResumable()),
			ConfirmationStatus::AllowedUnconfirmed => $this->store->put(LoginConfirmation::allowed($uid, $policyIds, $now, true)),
			default => LoginConfirmation::none($uid),
		};
	}

	/**
	 * The step-up of the current session, if any.
	 */
	public function current(): ?StepUpState {
		return $this->store->current();
	}

	/**
	 * A pending login changed while it waits: a code was sent or tried, the
	 * second factor or an administrator was asked.
	 */
	public function update(StepUpState $stepUp): bool {
		return $this->store->update($stepUp);
	}

	/**
	 * A login that needed no step-up proved more than the password anyway:
	 * core's second factor, or a known device.
	 *
	 * @param IConfirmationMethod::SECOND_FACTOR|IConfirmationMethod::KNOWN_DEVICE $by
	 */
	public function proved(string $uid, string $by): void {
		$this->store->put(LoginConfirmation::proven($uid, $by, $this->timeFactory->getTime()));
	}

	/**
	 * The login was confirmed: the session may continue.
	 */
	public function complete(StepUpState $stepUp, string $method): void {
		$this->store->removeStepUp();
		$this->store->put(LoginConfirmation::confirmed($stepUp->uid, $method, $stepUp->policies, $this->timeFactory->getTime()));
		$this->store->forget();
		$this->recordOutcome($stepUp->uid, $method, LoginHistory::STEP_UP_CONFIRMED);
		$this->audit->log('login of %s confirmed with %s', ['uid' => $stepUp->uid, 'method' => $method]);
	}

	/**
	 * The user gave up a login that waits for its confirmation: it ends
	 * without a detection, since nothing points to an attack.
	 */
	public function abandon(StepUpState $stepUp): void {
		$this->recordOutcome($stepUp->uid, LoginHistory::CONFIRMED_BY_NONE, LoginHistory::STEP_UP_FAILED);
		$this->store->forget();
		$this->store->removeStepUp();
		if ($this->userSession->isLoggedIn()) {
			$this->userSession->logout();
		}
		$this->audit->log('login of %s given up while it waited for its confirmation', ['uid' => $stepUp->uid]);
	}

	/**
	 * The login was not confirmed: record `step_up_failed`, which ends the
	 * session with its responses, and end it in any case.
	 */
	public function fail(StepUpState $stepUp, StepUpFailedRule $rule): ?Detection {
		$sessionId = $this->store->sessionId();
		$sessionTokenId = $this->coreSession->tokenId();
		$source = $this->addresses->current() ?? ($stepUp->ip === null ? null : SourceKey::tryFromIp($stepUp->ip));
		// Before the responses, which may end the session and its markers with it.
		$this->recordOutcome($stepUp->uid, LoginHistory::CONFIRMED_BY_NONE, LoginHistory::STEP_UP_FAILED);
		$detection = $this->record($this->failure($stepUp, $rule, $source, $sessionTokenId, self::SESSION_TTL, $stepUp->attempts));
		$this->store->forget($sessionId);
		if ($this->userSession->isLoggedIn()) {
			$this->store->removeStepUp();
			$this->userSession->logout();
		}
		$this->audit->log('login of %s ended: not confirmed (%s)', ['uid' => $stepUp->uid, 'rule' => $rule->value]);
		return $detection;
	}

	/**
	 * A login left waiting past its deadline, ended by the background job
	 * without its session: the same failure as {@see self::fail()}, with
	 * its session found through the login history.
	 *
	 * @param bool $detect whether to record `step_up_failed`; not while the protection is off
	 */
	public function abandoned(StepUpState $stepUp, bool $detect): void {
		$sessionTokenId = $this->history->failPending($stepUp->uid, $stepUp->started)?->sessionTokenId;
		if (!$detect) {
			$this->audit->log('login of %s ended while protection was off: it was left waiting for its confirmation', ['uid' => $stepUp->uid]);
			return;
		}
		$this->engine->handle($this->failure(
			$stepUp,
			StepUpFailedRule::Timeout,
			$stepUp->ip === null ? null : SourceKey::tryFromIp($stepUp->ip),
			$sessionTokenId,
			max(0, $stepUp->deadline - $stepUp->started),
			0,
			abandoned: true,
		));
		$this->audit->log('login of %s ended: it was left waiting for its confirmation', ['uid' => $stepUp->uid]);
	}

	/**
	 * End a refused login after it was shown why.
	 */
	public function endRefused(): void {
		$this->store->forget();
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
	public function resumed(string $uid, #[\SensitiveParameter] ?string $previousSessionId = null): LoginConfirmation {
		if ($previousSessionId !== null) {
			$this->store->forget($previousSessionId);
		}
		$now = $this->timeFactory->getTime();
		$resumed = $this->store->put(LoginConfirmation::ofStepUp(new StepUpState($uid, ConfirmationStatus::Resumed, [], $now, $now, $this->addresses->current()?->ip)));
		$this->audit->log('a session of %s whose login was never confirmed came back and is ended', ['uid' => $uid]);
		return $resumed;
	}

	/**
	 * Allowed without a method: record it, with the responses the policies
	 * ask for (tell the user and the administrators, require a new password).
	 * An app sending the password let in so serves apps only
	 * ({@see \OCA\IntrusionDetection\SessionState\Rules\StepUpRule}).
	 *
	 * @param list<string> $policyIds
	 * @return array{0: LoginConfirmation, 1: list<int>}
	 */
	private function allow(LoginContext $login, array $policyIds, NoMethodDecision $decision): array {
		$draft = new DetectionDraft(
			checkId: StepUpUnconfirmed::ID,
			source: $login->source,
			uid: $login->uid(),
			facts: new StepUpUnconfirmedFacts($policyIds, !$login->interactive, $decision->notify, $decision->forceChange),
			merge: DetectionDraft::MERGE_SOURCE_USER,
			userAgent: $login->userAgent,
		);
		$detection = $this->record($draft);
		$allowed = $this->store->put(LoginConfirmation::allowed($login->uid(), $policyIds, $this->timeFactory->getTime(), !$login->interactive));
		$this->audit->log('login of %s allowed without confirmation (%s)', ['uid' => $login->uid(), 'reasons' => implode(', ', $policyIds)]);
		return [$allowed, self::ids($detection)];
	}

	/**
	 * `step_up_failed` for a login that was not confirmed.
	 */
	private function failure(StepUpState $stepUp, StepUpFailedRule $rule, ?SourceKey $source, ?int $sessionTokenId, int $ttl, int $attempts, bool $abandoned = false): DetectionDraft {
		return new DetectionDraft(
			checkId: StepUpFailed::ID,
			source: $source,
			uid: $stepUp->uid,
			facts: new StepUpFailedFacts($rule, $stepUp->policies, $attempts, $stepUp->started, $ttl, $sessionTokenId, $abandoned),
			merge: DetectionDraft::MERGE_SOURCE_USER,
			sessionTokenId: $sessionTokenId,
		);
	}

	/**
	 * Without core's cookie test a refused app gets no session token:
	 * nothing could resume its session.
	 */
	private function clientResumable(): bool {
		return $this->request->getCookie(self::COOKIE_TEST) !== null;
	}

	/**
	 * Whether every reason lets an app of an account that could confirm in
	 * a browser log in from a familiar place.
	 *
	 * @param list<StepUpPolicy> $policies
	 */
	private static function allowFamiliarApps(array $policies): bool {
		foreach ($policies as $policy) {
			if (!$policy->allowsFamiliarApps()) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Record a detection and run its responses. A failure is logged: the
	 * decision about the login stands without its detection.
	 */
	private function record(DetectionDraft $draft): ?Detection {
		try {
			return $this->engine->handle($draft);
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
	 * @return list<int>
	 */
	private static function ids(?Detection $detection): array {
		return $detection === null ? [] : [$detection->getId()];
	}
}
