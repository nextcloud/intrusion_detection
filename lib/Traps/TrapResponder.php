<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Traps;

use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\Check\Checks\TrapUrl;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Guard\DeferredHits;
use OCA\IntrusionDetection\Guard\IDeferredResponder;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;
use OCP\IUserSession;
use OCP\Security\Guard\GuardDecision;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Turns a trap URL hit into a detection, with the configured responses (a
 * block by default), and refuses the request when its address is blocked.
 *
 * A request that presents credentials (an Authorization header, a session
 * or remember-me cookie) waits until it is known whether it is logged in
 * ({@see DeferredHits}): logged-in users and clients never trip the check,
 * but a made-up cookie or password does not hide a scanner either. A
 * request that never logs in is handled as not logged in.
 */
class TrapResponder implements IDeferredResponder {
	public const CONTEXT_KEY = 'trap_url.pending';

	private bool $shutdownRegistered = false;

	public function __construct(
		private readonly ResponseEngine $engine,
		private readonly AddressResolver $resolver,
		private readonly RequestContext $context,
		private readonly ITimeFactory $timeFactory,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * Record a hit of a request that is not logged in.
	 *
	 * @return ?GuardDecision the refusal when the address is blocked now
	 */
	public function anonymous(PendingTrapHit $hit): ?GuardDecision {
		$detection = $this->engine->handle(new DetectionDraft(
			checkId: TrapUrl::ID,
			source: $hit->source,
			facts: $hit->facts,
			merge: DetectionDraft::MERGE_SOURCE,
			userAgent: $hit->userAgent,
			lure: $hit->lure,
		));
		if ($detection === null || !$detection->isEnforced()) {
			return null;
		}
		$verdict = $this->resolver->resolve($hit->source);
		$now = $this->timeFactory->getTime();
		return $verdict->isDenied($now) ? GuardDecision::deny($verdict->denyUntil - $now, $verdict->reference) : null;
	}

	/**
	 * Keep a hit until the request knows whether it is logged in.
	 */
	public function defer(PendingTrapHit $hit): void {
		$this->context->set(self::CONTEXT_KEY, $hit);
		if (!$this->shutdownRegistered) {
			$this->shutdownRegistered = true;
			$this->registerShutdown($this->resolveAtShutdown(...));
		}
	}

	#[\Override]
	public function resolve(?IUser $user): ?GuardDecision {
		$hit = $this->context->get(self::CONTEXT_KEY);
		if (!$hit instanceof PendingTrapHit) {
			return null;
		}
		$this->context->set(self::CONTEXT_KEY, null);
		if ($user !== null) {
			return null;
		}
		$decision = $this->anonymous($hit);
		if ($decision !== null) {
			$this->context->refuse($decision);
		}
		return $decision;
	}

	/**
	 * The last chance for a waiting hit: at the end of the request the
	 * session knows whether the request was logged in.
	 */
	public function resolveAtShutdown(): void {
		if (!$this->context->get(self::CONTEXT_KEY) instanceof PendingTrapHit) {
			return;
		}
		try {
			$this->resolve($this->container->get(IUserSession::class)->getUser());
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not record a trap URL hit', ['exception' => $e]);
		}
	}

	protected function registerShutdown(\Closure $callback): void {
		register_shutdown_function($callback);
	}
}
