<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState\Rules;

use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCP\IUserSession;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Links a browser session's token to its row of the login history on the
 * session's first request: core creates the token only after the login
 * event. The marker goes with it, so that later requests of the session
 * have nothing to check. Never blocks a request.
 */
class LoginHistoryRule implements ISessionStateRule {
	public function __construct(
		private readonly IUserSession $userSession,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function check(SessionMarkers $state, RequestTarget $target): ?SessionBlock {
		$marker = $state->all()[SessionMarkers::LOGIN_HISTORY] ?? null;
		if (!is_array($marker)) {
			return null;
		}
		if (($marker['linked'] ?? false) === true) {
			// A marker that is linked already has nothing left to do.
			$state->remove(SessionMarkers::LOGIN_HISTORY);
			return null;
		}
		try {
			$this->container->get(LoginHistory::class)->linkSession($this->userSession->getUser()?->getUID());
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not link a login to its session', ['exception' => $e]);
		}
		return null;
	}
}
