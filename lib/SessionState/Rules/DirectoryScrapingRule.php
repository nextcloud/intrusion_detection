<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState\Rules;

use OCA\IntrusionDetection\Check\Checks\DirectoryScrapingDetector;
use OCA\IntrusionDetection\Sensitive\DirectoryRoutes;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\IRequest;
use OCP\IUserSession;
use Psr\Container\ContainerInterface;

/**
 * Counts the requests of logged-in accounts that read the user directory
 * ({@see DirectoryScrapingDetector}), and refuses them with 429 while the
 * account is above a limit.
 *
 * It hooks into the session-state middleware and WebDAV plugin, which run
 * for every logged-in request anyway, once routing and authentication are
 * done: the route and the account are known, so the check needs no request
 * guard of its own (a guard runs before authentication and would have to
 * parse every URL). For any other route it costs one array lookup on the
 * route name; WebDAV requests other than REPORT and PROPFIND cost two
 * string comparisons.
 */
class DirectoryScrapingRule implements ISessionStateRule {
	public function __construct(
		private readonly IRequest $request,
		private readonly IUserSession $userSession,
		private readonly ContainerInterface $container,
	) {
	}

	#[\Override]
	public function check(SessionState $state, RequestTarget $target): ?SessionBlock {
		$group = $target->dav
			? DirectoryRoutes::davGroup($target->httpMethod, $target->uri, $this->request->getHeader('Depth'))
			: DirectoryRoutes::group($this->request->getParam('_route'), fn (): mixed => $this->request->getParam('providerId'));
		if ($group === null) {
			return null;
		}
		$uid = $this->userSession->getUser()?->getUID();
		if ($uid === null) {
			return null;
		}
		return $this->container->get(DirectoryScrapingDetector::class)->count($uid, $group);
	}
}
