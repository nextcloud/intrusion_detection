<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Guard;

use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PayloadResponder;
use OCA\IntrusionDetection\Traps\TrapResponder;
use OCP\IUser;
use OCP\Security\Guard\GuardDecision;
use Psr\Container\ContainerInterface;

/**
 * The hits of request guards that carried credentials: an injection probe
 * or a trap URL in a request that claims to be logged in. At guard time a
 * cookie or a password only says that the request presents one, so the hit
 * waits until the request knows its user, and is decided at the first of:
 * a successful login ({@see \OCA\IntrusionDetection\Listener\PayloadLoginListener}),
 * the start of a controller ({@see \OCA\IntrusionDetection\Middleware\PayloadMiddleware}),
 * the start of a WebDAV method ({@see \OCA\IntrusionDetection\Dav\GuardDecisionPlugin}),
 * or the end of the request. A refusal decided early is kept in the request
 * context, so the later steps refuse the request too.
 */
class DeferredHits {
	/** The responders, by the request context key under which their hit waits */
	private const RESPONDERS = [
		PayloadResponder::CONTEXT_KEY => PayloadResponder::class,
		TrapResponder::CONTEXT_KEY => TrapResponder::class,
	];

	public function __construct(
		private readonly RequestContext $context,
		private readonly ContainerInterface $container,
	) {
	}

	/**
	 * Whether a hit waits for the login. Costs an array lookup per responder
	 * and loads nothing.
	 */
	public static function isPending(RequestContext $context): bool {
		foreach (array_keys(self::RESPONDERS) as $key) {
			if ($context->get($key) !== null) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Decide the waiting hits now that the user is known.
	 *
	 * @param ?IUser $user the logged-in user, null when the request is not logged in
	 * @return ?GuardDecision the refusal of the request, also one decided before
	 */
	public function resolve(?IUser $user): ?GuardDecision {
		foreach (self::RESPONDERS as $key => $class) {
			if ($this->context->get($key) !== null) {
				$responder = $this->container->get($class);
				if ($responder instanceof IDeferredResponder) {
					$responder->resolve($user);
				}
			}
		}
		return $this->context->refusal();
	}
}
