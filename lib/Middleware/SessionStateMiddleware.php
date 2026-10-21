<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Middleware;

use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\SessionState\SessionStateRules;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\Response;
use OCP\AppFramework\Http\TooManyRequestsResponse;
use OCP\AppFramework\Middleware;
use OCP\AppFramework\OCS\OCSException;
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
 * A block with data (a sensitive action that needs confirmation) puts it
 * into the JSON or the OCS data, and also redirects a submitted form.
 * A rate limit answers 429 with `Retry-After` instead: core's "too many
 * requests" page for a browser, an OCS 429 for OCS, and JSON otherwise.
 *
 * The middleware is built for every AppFramework request, so it only takes
 * light dependencies, and does nothing but one session read while no rule
 * applies. A failure lets the request pass.
 */
class SessionStateMiddleware extends Middleware {
	/** Seconds for the Retry-After header of a rate-limited OCS answer, which core's OCS middleware builds */
	private ?int $retryAfter = null;

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
		if ($block->isRateLimit()) {
			return $this->rateLimited($controller, $block);
		}
		if ($controller instanceof OCSController) {
			if ($block->data !== []) {
				return $this->ocsResponse($controller, $block);
			}
			// Core's OCS middleware turns this into an OCS 403 that carries the message.
			return new JSONResponse(['message' => $block->error], Http::STATUS_FORBIDDEN);
		}
		if ($block->redirectUrl !== null && ($this->isPageNavigation() || ($block->data !== [] && $this->isFormSubmission()))) {
			return new RedirectResponse($block->redirectUrl);
		}
		return new JSONResponse(['error' => $block->error, ...$block->data], Http::STATUS_FORBIDDEN);
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
	private function rateLimited(Controller $controller, SessionBlock $block): Response {
		$this->retryAfter = $block->retryAfter;
		if ($controller instanceof OCSController) {
			throw new OCSException($block->message, Http::STATUS_TOO_MANY_REQUESTS);
		}
		$response = $this->isPageNavigation()
			? new TooManyRequestsResponse()
			: new JSONResponse(['error' => $block->error], Http::STATUS_TOO_MANY_REQUESTS);
		$response->addHeader('Retry-After', (string)$block->retryAfter);
		return $response;
	}

	/**
	 * An OCS 403 whose data says why and what to do, in the format the
	 * client asked for. Core's OCS middleware passes OCS responses through.
	 */
	private function ocsResponse(OCSController $controller, SessionBlock $block): Response {
		$format = $this->request->getFormat();
		if ($format === null || !$controller->isResponderRegistered($format)) {
			$format = 'xml';
		}
		return $controller->buildResponse(new DataResponse(['error' => $block->error, ...$block->data], Http::STATUS_FORBIDDEN), $format);
	}

	/**
	 * A browser submitting a form, such as the "Grant access" page of a
	 * client login, as opposed to a script.
	 */
	private function isFormSubmission(): bool {
		return $this->request->getMethod() === 'POST'
			&& stripos($this->request->getHeader('Accept'), 'html') !== false
			&& $this->request->getHeader('X-Requested-With') === ''
			&& $this->request->getHeader('OCS-APIREQUEST') === '';
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
