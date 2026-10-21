<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Sensitive;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\ConfirmationPolicy;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;
use OCP\IUserSession;
use Psr\Log\LoggerInterface;

/**
 * Confirming a sensitive action in a running session, on the confirm page
 * (concept sections 11.13 and 15.2). It uses the confirmation methods of
 * logins, in their order ({@see ConfirmationPolicy}): the second factor
 * (asked again through core), an email code, an administrator's approval.
 * A remembered device does not count: the action runs on that very device.
 *
 * The confirmation in progress is a {@see StepUpState} with the policy
 * "sensitive_action", kept apart from a login's step-up
 * ({@see SessionState::SENSITIVE_PENDING}), so the session works normally
 * while it waits. Too many wrong codes, or an administrator who rejects it,
 * fail it like a login confirmation: `step_up_failed` with its responses,
 * and the session ends.
 */
class SensitiveConfirmations {
	public function __construct(
		private readonly SessionState $state,
		private readonly SensitiveSession $sensitive,
		private readonly ConfirmationPolicy $policy,
		private readonly ResponseEngine $engine,
		private readonly StepUpFailed $failedCheck,
		private readonly Settings $settings,
		private readonly CurrentSession $currentSession,
		private readonly RemoteAddressResolver $addresses,
		private readonly IUserSession $userSession,
		private readonly ITimeFactory $timeFactory,
		private readonly AuditLogger $audit,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * The methods that can confirm a sensitive action of the account, in order.
	 *
	 * @return list<IConfirmationMethod>
	 */
	public function methodsFor(IUser $user): array {
		return $this->policy->methodsFor($user, StepUpPolicy::SensitiveAction);
	}

	/**
	 * The confirmation in progress, unless it is someone else's or timed out.
	 */
	public function current(IUser $user): ?StepUpState {
		$data = $this->state->get(SessionState::SENSITIVE_PENDING);
		$pending = $data === null ? null : StepUpState::fromArray($data);
		if ($pending === null) {
			return null;
		}
		if ($pending->uid !== $user->getUID() || $pending->deadline <= $this->timeFactory->getTime()) {
			$this->state->remove(SessionState::SENSITIVE_PENDING);
			return null;
		}
		return $pending;
	}

	/**
	 * Start confirming: the first method that needs nothing from the user
	 * to begin is begun (an email code is sent, an administrator asked).
	 * The second factor is offered on the page instead, since asking for it
	 * takes the browser to core's challenge.
	 *
	 * @return ?StepUpState null when nothing can confirm it
	 */
	public function start(IUser $user): ?StepUpState {
		$methods = $this->methodsFor($user);
		if ($methods === []) {
			return null;
		}
		$now = $this->timeFactory->getTime();
		$pending = new StepUpState(
			$user->getUID(),
			StepUpState::PENDING,
			[StepUpPolicy::SensitiveAction->value],
			$now,
			$now + $this->settings->getInt(GlobalSettings::STEP_UP_SESSION_TTL),
			$this->addresses->current()?->ip,
			array_map(static fn (IConfirmationMethod $m): string => $m->id(), $methods),
		);
		if ($methods[0]->id() !== IConfirmationMethod::SECOND_FACTOR) {
			foreach ($methods as $method) {
				if ($method->begin($user, $pending) === IConfirmationMethod::PENDING) {
					break;
				}
			}
		}
		$this->save($pending);
		$this->audit->log('%s asked to confirm a sensitive action, with %s', ['uid' => $user->getUID(), 'methods' => implode(', ', $pending->methods)]);
		return $pending;
	}

	public function save(StepUpState $pending): bool {
		return $this->state->set(SessionState::SENSITIVE_PENDING, $pending->toArray());
	}

	/**
	 * Confirmed: sensitive actions may go ahead for `sensitive_confirm_ttl`.
	 */
	public function complete(StepUpState $pending, string $method): void {
		$this->state->remove(SessionState::SENSITIVE_PENDING);
		$this->sensitive->confirmed($this->state, $pending->uid, $method);
		$this->audit->log('sensitive action of %s confirmed with %s', ['uid' => $pending->uid, 'method' => $method]);
	}

	/**
	 * The user gave up: nothing happens but the confirmation ending.
	 */
	public function abandon(StepUpState $pending): void {
		$this->state->remove(SessionState::SENSITIVE_PENDING);
		$this->audit->log('confirmation of a sensitive action given up by %s', ['uid' => $pending->uid]);
	}

	/**
	 * Not confirmed: too many wrong codes, or an administrator rejected it.
	 * Recorded as `step_up_failed`, whose responses end the session; it is
	 * ended in any case.
	 *
	 * @param StepUpFailed::RULE_ATTEMPTS|StepUpFailed::RULE_REJECTED $rule
	 */
	public function fail(StepUpState $pending, string $rule): ?Detection {
		$this->state->remove(SessionState::SENSITIVE_PENDING);
		$sessionTokenId = $this->currentSession->tokenId();
		$draft = new DetectionDraft(
			checkId: StepUpFailed::ID,
			source: $this->addresses->current(),
			uid: $pending->uid,
			facts: [
				'rule' => $rule,
				'policies' => $pending->policies,
				'attempts' => $pending->attempts,
				'started' => $pending->started,
				'action' => true,
				'sessionTokenId' => $sessionTokenId,
			],
			merge: DetectionDraft::MERGE_SOURCE_USER,
			sessionTokenId: $sessionTokenId,
		);
		$detection = null;
		try {
			$detection = $this->engine->handle($draft, $this->failedCheck->responsesFor($draft, $this->settings->responses(StepUpFailed::ID), []));
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not record a failed confirmation', ['exception' => $e]);
		}
		if ($this->userSession->isLoggedIn()) {
			$this->userSession->logout();
		}
		$this->audit->log('session of %s ended: a sensitive action was not confirmed (%s)', ['uid' => $pending->uid, 'rule' => $rule]);
		return $detection;
	}
}
