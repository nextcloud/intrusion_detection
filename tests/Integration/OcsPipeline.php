<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\AppFramework\Bootstrap\Coordinator;
use OC\AppFramework\Middleware\MiddlewareDispatcher;
use OC\AppFramework\Middleware\OCSMiddleware;
use OC\AppFramework\OCS\BaseResponse;
use OCA\IntrusionDetection\AppInfo\Application;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\OCSController;
use OCP\IRequest;
use OCP\Server;

/**
 * Calls a controller method the way core's dispatcher answers an OCS v2
 * request in JSON: the app's own middlewares and core's OCS middleware turn
 * exceptions and data into the response, which is rendered. The security
 * middlewares (admin, CSRF, password confirmation) are left out; the route
 * table tests pin those.
 */
trait OcsPipeline {
	/**
	 * @param array<array-key, mixed> $arguments
	 * @return array{status: int, message: ?string, data: mixed}
	 */
	protected function ocs(OCSController $controller, string $method, array $arguments = []): array {
		$dispatcher = $this->ocsDispatcher();
		$dispatcher->beforeController($controller, $method);
		try {
			$response = $controller->$method(...$arguments);
			if ($response instanceof DataResponse) {
				$response = $controller->buildResponse($response, 'json');
			}
		} catch (\Exception $e) {
			$response = $dispatcher->afterException($controller, $method, $e);
		}
		$response = $dispatcher->afterController($controller, $method, $response);
		$body = $response->render();
		if ($response instanceof BaseResponse) {
			$ocs = json_decode($body, true, flags: JSON_THROW_ON_ERROR)['ocs'];
			return ['status' => $response->getStatus(), 'message' => $ocs['meta']['message'], 'data' => $ocs['data']];
		}
		if ($response instanceof JSONResponse) {
			return ['status' => $response->getStatus(), 'message' => null, 'data' => json_decode($body, true, flags: JSON_THROW_ON_ERROR)];
		}
		return ['status' => $response->getStatus(), 'message' => null, 'data' => $body];
	}

	/**
	 * Core's OCS middleware for a v2 JSON request, and the middlewares the
	 * app registers for its own controllers.
	 */
	private function ocsDispatcher(): MiddlewareDispatcher {
		$request = $this->createMock(IRequest::class);
		$request->method('getScriptName')->willReturn('/ocs/v2.php');
		$request->method('getFormat')->willReturn('json');
		$dispatcher = new MiddlewareDispatcher();
		$dispatcher->registerMiddleware(new OCSMiddleware($request));
		$container = (new Application())->getContainer();
		foreach (Server::get(Coordinator::class)->getRegistrationContext()?->getMiddlewareRegistrations() ?? [] as $registration) {
			if ($registration->getAppId() === Application::APP_ID && !$registration->isGlobal()) {
				$dispatcher->registerMiddleware($container->get($registration->getService()));
			}
		}
		return $dispatcher;
	}
}
