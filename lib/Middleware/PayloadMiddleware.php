<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Middleware;

use OCA\IntrusionDetection\Guard\DeferredHits;
use OCA\IntrusionDetection\Login\RequestContext;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\Response;
use OCP\AppFramework\Http\TextPlainResponse;
use OCP\AppFramework\Middleware;
use OCP\AppFramework\OCSController;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Decides the guard hits of a request with credentials (an injection probe,
 * a trap URL, {@see DeferredHits}) as soon as a controller is about to run,
 * when the user is known. If the address is blocked by one, the controller
 * does not run and the client gets the same answer as from a request guard.
 *
 * A hit already decided at the login (Basic auth, app passwords, tokens) is
 * refused here too. Registered for every app's controllers. On requests
 * without a hit it costs three property and array lookups.
 */
class PayloadMiddleware extends Middleware {
	public function __construct(
		private readonly RequestContext $context,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function beforeController(Controller $controller, string $methodName): void {
		$decided = $this->context->refusal();
		if ($decided !== null) {
			throw new PayloadBlockedException($decided);
		}
		if (!DeferredHits::isPending($this->context)) {
			return;
		}
		try {
			$decision = $this->container->get(DeferredHits::class)->resolve($this->container->get(IUserSession::class)->getUser());
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not record a request guard hit', ['exception' => $e]);
			return;
		}
		if ($decision !== null) {
			throw new PayloadBlockedException($decision);
		}
	}

	#[\Override]
	public function afterException(Controller $controller, string $methodName, \Exception $exception): Response {
		if (!$exception instanceof PayloadBlockedException) {
			throw $exception;
		}
		// The same text core shows when a request guard refuses a request.
		$text = $this->container->get(IFactory::class)->get('lib')->t(
			'Access from your network is temporarily blocked. If you think this is a mistake, contact your administrator and give them this reference: %s',
			[$exception->decision->getReference()]
		);
		// OCS turns every 403 into its own format and keeps only a JSON response's message.
		$response = $controller instanceof OCSController
			? new JSONResponse(['message' => $text], Http::STATUS_FORBIDDEN)
			: new TextPlainResponse($text, Http::STATUS_FORBIDDEN);
		$response->addHeader('Retry-After', (string)$exception->decision->getRetryAfter());
		return $response;
	}
}
