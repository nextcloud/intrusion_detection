<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Payload;

use OCA\IntrusionDetection\Check\Checks\InjectionProbe;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;
use OCP\IUserSession;
use OCP\Security\Guard\GuardDecision;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Turns a payload hit into a detection, and decides the hits of requests
 * with credentials once the request knows its user.
 *
 * - Not logged in: a detection merged per address and hour, the configured
 *   responses (a block by default), and a refusal of the request itself.
 * - Logged in: a detection naming the user, merged per address, user and
 *   hour, in the mode for logged-in users (Observe by default).
 *
 * A hit with credentials is resolved at the first of: a successful login
 * ({@see \OCA\IntrusionDetection\Listener\PayloadLoginListener}), the start of
 * a controller ({@see \OCA\IntrusionDetection\Middleware\PayloadMiddleware}),
 * or the end of the request, for entry points without controllers such as
 * WebDAV. A request that never logs in is handled as not logged in. A
 * refusal decided at the login is kept, so the middleware still refuses
 * the request.
 */
class PayloadResponder {
	public const CONTEXT_KEY = 'injection_probe.pending';
	/** The refusal of a hit that was decided before a controller ran, for the middleware */
	public const DECISION_KEY = 'injection_probe.decision';

	private bool $shutdownRegistered = false;

	public function __construct(
		private readonly ResponseEngine $engine,
		private readonly PayloadSettings $settings,
		private readonly RequestContext $context,
		private readonly ITimeFactory $timeFactory,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * Record a hit of a request that is not logged in.
	 *
	 * @param ?string $credential what the request carried if it claimed to be logged in, see PendingHit::CREDENTIAL_*
	 * @return ?GuardDecision the refusal when the address is blocked now
	 */
	public function anonymous(PayloadHit $hit, SourceKey $source, ?string $userAgent, ?string $credential = null): ?GuardDecision {
		$facts = $hit->facts() + ['authenticated' => false, 'credential' => $credential];
		$draft = new DetectionDraft(
			checkId: InjectionProbe::ID,
			source: $source,
			facts: $facts,
			merge: DetectionDraft::MERGE_SOURCE,
			mergeWindow: 3600,
			userAgent: $userAgent,
		);
		return $this->refusal($this->engine->handle($draft, null, $this->settings->anonymousMode()));
	}

	/**
	 * Record a hit of a logged-in user.
	 *
	 * @param PendingHit::CREDENTIAL_* $credential
	 */
	public function authenticated(PayloadHit $hit, SourceKey $source, string $uid, string $credential, ?string $userAgent): ?GuardDecision {
		$facts = $hit->facts() + ['authenticated' => true, 'credential' => $credential];
		$draft = new DetectionDraft(
			checkId: InjectionProbe::ID,
			source: $source,
			uid: $uid,
			facts: $facts,
			merge: DetectionDraft::MERGE_SOURCE_USER,
			mergeWindow: 3600,
			userAgent: $userAgent,
		);
		return $this->refusal($this->engine->handle($draft, null, $this->settings->authenticatedMode()));
	}

	/**
	 * Keep a hit until the request knows whether it is logged in.
	 */
	public function defer(PendingHit $pending): void {
		$this->context->set(self::CONTEXT_KEY, $pending);
		if (!$this->shutdownRegistered) {
			$this->shutdownRegistered = true;
			$this->registerShutdown($this->resolveAtShutdown(...));
		}
	}

	public function hasPending(): bool {
		return $this->context->get(self::CONTEXT_KEY) instanceof PendingHit;
	}

	/**
	 * Decide the pending hit, if any, now that the user is known.
	 *
	 * @param ?IUser $user the logged-in user, null when the request is not logged in
	 * @return ?GuardDecision the refusal when the address is blocked now
	 */
	public function resolve(?IUser $user): ?GuardDecision {
		$pending = $this->context->get(self::CONTEXT_KEY);
		if (!$pending instanceof PendingHit) {
			return null;
		}
		$this->context->set(self::CONTEXT_KEY, null);
		$decision = $user === null
			? $this->anonymous($pending->hit, $pending->source, $pending->userAgent, $pending->credential)
			: $this->authenticated($pending->hit, $pending->source, $user->getUID(), $pending->credential, $pending->userAgent);
		if ($decision !== null) {
			$this->context->set(self::DECISION_KEY, $decision);
		}
		return $decision;
	}

	/**
	 * The last chance for a pending hit: at the end of the request the
	 * session knows whether the request was logged in.
	 */
	public function resolveAtShutdown(): void {
		if (!$this->hasPending()) {
			return;
		}
		try {
			$this->resolve($this->container->get(IUserSession::class)->getUser());
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not record an injection probe', ['exception' => $e]);
		}
	}

	protected function registerShutdown(\Closure $callback): void {
		register_shutdown_function($callback);
	}

	/**
	 * The refusal for the current request when the detection blocked its address.
	 */
	private function refusal(?Detection $detection): ?GuardDecision {
		if ($detection === null || !$detection->isEnforced()) {
			return null;
		}
		$now = $this->timeFactory->getTime();
		foreach ($detection->getActionList() as $action) {
			if ($action['type'] !== ResponseType::Ban->value || !$action['enforced'] || !is_array($action['ref'] ?? null)) {
				continue;
			}
			foreach ((array)($action['ref']['bans'] ?? []) as $ban) {
				if (is_array($ban) && (int)($ban['until'] ?? 0) > $now && is_string($ban['reference'] ?? null)) {
					return GuardDecision::deny((int)$ban['until'] - $now, $ban['reference']);
				}
			}
		}
		return null;
	}
}
