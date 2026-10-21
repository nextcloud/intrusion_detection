<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState\Rules;

use OCA\IntrusionDetection\Sensitive\SensitiveActions;
use OCA\IntrusionDetection\Sensitive\SensitiveRoutes;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\IRequest;
use OCP\IUserSession;
use Psr\Container\ContainerInterface;

/**
 * Sensitive actions in risky sessions need a fresh confirmation, and new
 * devices are refused during lockdown (concept sections 11.13 and 11.14).
 *
 * For any other route it costs one array lookup on the route name; the
 * decision ({@see SensitiveActions}) is loaded only for the routes in
 * {@see SensitiveRoutes}. WebDAV has no sensitive actions.
 */
class SensitiveActionRule implements ISessionStateRule {
	public function __construct(
		private readonly IRequest $request,
		private readonly IUserSession $userSession,
		private readonly ContainerInterface $container,
	) {
	}

	#[\Override]
	public function check(SessionState $state, RequestTarget $target): ?SessionBlock {
		if ($target->dav) {
			return null;
		}
		$route = $this->request->getParam('_route');
		if (!is_string($route) || !isset(SensitiveRoutes::ROUTES[$route])) {
			return null;
		}
		$uid = $this->userSession->getUser()?->getUID();
		if ($uid === null) {
			return null;
		}
		return $this->container->get(SensitiveActions::class)->check($state, $route, $uid, $target->uri);
	}
}
