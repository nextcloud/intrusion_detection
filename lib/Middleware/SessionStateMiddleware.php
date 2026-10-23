<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Middleware;

use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionGate;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\Response;
use OCP\AppFramework\Http\TooManyRequestsResponse;
use OCP\AppFramework\Middleware;
use OCP\AppFramework\OCS\OCSException;
use OCP\AppFramework\OCSController;
use OCP\IRequest;

/**
 * Applies the session gate ({@see SessionGate}) to every AppFramework
 * request of a logged-in user, in every app.
 *
 * It is registered as a global middleware, so it runs after core's
 * security and two-factor middlewares: a login that still needs its second
 * factor is sent to the challenge first. A blocked browser navigation is
 * redirected where the rule says; other requests get 403 with
 * `{"error": "…"}`, OCS requests an OCS 403 with the error as its message.
 * A rate limit answers 429 with `Retry-After` instead: core's "too many
 * requests" page for a browser, an OCS 429 for OCS, and JSON otherwise.
 *
 * The middleware is built for every AppFramework request, so it only takes
 * light dependencies, and does nothing but one session read while no rule
 * applies.
 */
class SessionStateMiddleware extends Middleware {
	/** Seconds for the Retry-After header of a rate-limited OCS answer, which core's OCS middleware builds */
	private ?int $retryAfter = null;

	public function __construct(
		private readonly SessionGate $gate,
		private readonly IRequest $request,
	) {
	}

	#[\Override]
	public function beforeController(Controller $controller, string $methodName): void {
		$block = $this->gate->decide($controller, $methodName);
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
		if ($block->isRateLimit()) {
			return $this->rateLimited($controller, $methodName, $block);
		}
		if ($controller instanceof OCSController) {
			// Core's OCS middleware turns this into an OCS 403 that carries the message.
			return new JSONResponse(['message' => $block->error], Http::STATUS_FORBIDDEN);
		}
		if ($block->redirectUrl !== null && $this->isPageNavigation($controller, $methodName)) {
			return new RedirectResponse($block->redirectUrl);
		}
		return new JSONResponse(['error' => $block->error], Http::STATUS_FORBIDDEN);
	}

	#[\Override]
	public function afterController(Controller $controller, string $methodName, Response $response): Response {
		if ($this->retryAfter !== null) {
			$response->addHeader('Retry-After', (string)$this->retryAfter);
		}
		return $response;
	}

	/**
	 * @throws OCSException for OCS controllers, which core's OCS middleware turns into an OCS 429
	 */
	private function rateLimited(Controller $controller, string $methodName, SessionBlock $block): Response {
		$this->retryAfter = $block->retryAfter;
		if ($controller instanceof OCSController) {
			throw new OCSException($block->message, Http::STATUS_TOO_MANY_REQUESTS);
		}
		$response = $this->isPageNavigation($controller, $methodName)
			? new TooManyRequestsResponse()
			: new JSONResponse(['error' => $block->error], Http::STATUS_TOO_MANY_REQUESTS);
		$response->addHeader('Retry-After', (string)$block->retryAfter);
		return $response;
	}

	private function isPageNavigation(Controller $controller, string $methodName): bool {
		return RequestTarget::app($controller, $methodName, $this->request->getMethod(), $this->request->getRequestUri())->isPageNavigation($this->request);
	}
}
