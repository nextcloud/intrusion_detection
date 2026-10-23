<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState;

use OCA\IntrusionDetection\Login\SessionMarkers;
use OCP\AppFramework\Controller;
use OCP\IRequest;
use OCP\IUserSession;
use Psr\Log\LoggerInterface;

/**
 * Whether a request of a logged-in user may proceed: the one decision the
 * session-state middleware (AppFramework) and the WebDAV plugin ask for.
 * Requests of visitors are not looked at.
 *
 * It never throws. An error lets the request pass: a broken check must not
 * lock everybody out.
 */
class SessionGate {
	public function __construct(
		private readonly SessionStateRules $rules,
		private readonly SessionMarkers $markers,
		private readonly IUserSession $userSession,
		private readonly IRequest $request,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @return ?SessionBlock why the request may not proceed, or null to let it pass
	 */
	public function decide(Controller $controller, string $methodName): ?SessionBlock {
		try {
			if (!$this->userSession->isLoggedIn()) {
				return null;
			}
			return $this->rules->check($this->markers, RequestTarget::app($controller, $methodName, $this->request->getMethod(), $this->request->getRequestUri()));
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not check the session state', ['exception' => $e]);
			return null;
		}
	}

	/**
	 * @return ?SessionBlock why the WebDAV request may not proceed, or null to let it pass
	 */
	public function decideDav(string $method, string $uri): ?SessionBlock {
		try {
			if (!$this->userSession->isLoggedIn()) {
				return null;
			}
			return $this->rules->checkDav($this->markers, $method, $uri);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not check the session state of a WebDAV request', ['exception' => $e]);
			return null;
		}
	}
}
