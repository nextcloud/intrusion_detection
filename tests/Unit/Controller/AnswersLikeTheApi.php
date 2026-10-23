<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Controller;

use OCA\IntrusionDetection\Middleware\ApiErrorMiddleware;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCSController;
use OCP\IRequest;
use OCP\L10N\IFactory;
use OCP\Server;

/**
 * The answer a client gets from a controller method: its response, or
 * the error {@see ApiErrorMiddleware} makes of the exception it throws.
 */
trait AnswersLikeTheApi {
	/**
	 * @param \Closure(): DataResponse $call
	 */
	protected function answer(\Closure $call): DataResponse {
		try {
			return $call();
		} catch (\Exception $e) {
			$controller = $this->createMock(OCSController::class);
			$controller->method('buildResponse')->willReturnArgument(0);
			$controller->method('isResponderRegistered')->willReturn(true);
			$request = $this->createMock(IRequest::class);
			$request->method('getFormat')->willReturn('json');
			$response = (new ApiErrorMiddleware($request, Server::get(IFactory::class)->get('intrusion_detection', 'en')))->afterException($controller, 'call', $e);
			$this->assertInstanceOf(DataResponse::class, $response);
			return $response;
		}
	}
}
