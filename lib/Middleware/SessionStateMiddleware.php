<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Middleware;

use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\SessionState\SessionStateRules;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\Response;
use OCP\AppFramework\Middleware;
use OCP\AppFramework\OCSController;
use OCP\IRequest;
use OCP\IUserSession;
use Psr\Log\LoggerInterface;

/**
 * Applies the session-state rules ({@see SessionStateRules}) to every
 * AppFramework request of a logged-in user, in every app.
 *
 * It is registered as a global middleware, so it runs after core's
 * security and two-factor middlewares: a login that still needs its second
 * factor is sent to the challenge first. A blocked browser navigation is
 * redirected where the rule says; other requests get 403 with
 * `{"error": "…"}`, OCS requests an OCS 403 with the error as its message.
 *
 * The middleware is built for every AppFramework request, so it only takes
 * light dependencies, and does nothing but one session read while no rule
 * applies. A failure lets the request pass.
 */
class SessionStateMiddleware extends Middleware {
	public function __construct(
		private readonly SessionStateRules $rules,
		private readonly SessionState $state,
		private readonly IUserSession $userSession,
		private readonly IRequest $request,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function beforeController(Controller $controller, string $methodName): void {
		try {
			if (!$this->userSession->isLoggedIn()) {
				return;
			}
			$target = RequestTarget::app($controller, $methodName, $this->request->getMethod(), $this->request->getRequestUri());
			$block = $this->rules->check($this->state, $target);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not check the session state', ['exception' => $e]);
			return;
		}
		if ($block !== null) {
			throw new SessionBlockedException($block);
		}
	}

	#[\Override]
	public function afterException(Controller $controller, string $methodName, \Exception $exception): Response {
		if (!$exception instanceof SessionBlockedException) {
			throw $exception;
		}
		$block = $exception->block;
		if ($controller instanceof OCSController) {
			// Core's OCS middleware turns this into an OCS 403 that carries the message.
			return new JSONResponse(['message' => $block->error], Http::STATUS_FORBIDDEN);
		}
		if ($block->redirectUrl !== null && $this->isPageNavigation()) {
			return new RedirectResponse($block->redirectUrl);
		}
		return new JSONResponse(['error' => $block->error], Http::STATUS_FORBIDDEN);
	}

	/**
	 * A browser loading a page, as opposed to a script asking for data.
	 */
	private function isPageNavigation(): bool {
		$method = $this->request->getMethod();
		return ($method === 'GET' || $method === 'HEAD')
			&& stripos($this->request->getHeader('Accept'), 'html') !== false
			&& $this->request->getHeader('OCS-APIREQUEST') === '';
	}
}
