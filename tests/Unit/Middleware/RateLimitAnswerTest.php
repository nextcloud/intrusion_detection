<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Middleware;

use OCA\IntrusionDetection\Dav\SessionStatePlugin;
use OCA\IntrusionDetection\Middleware\SessionBlockedException;
use OCA\IntrusionDetection\Middleware\SessionStateMiddleware;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\SessionState\SessionStateRules;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\TooManyRequestsResponse;
use OCP\AppFramework\OCS\OCSException;
use OCP\AppFramework\OCSController;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserSession;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Sabre\HTTP\RequestInterface;
use Sabre\HTTP\Response;
use Test\TestCase;

/**
 * A rate limit from a session-state rule (directory scraping) is answered
 * with 429 and Retry-After on every kind of request.
 */
class RateLimitAnswerTest extends TestCase {
	private string $accept = 'application/json';
	private SessionStateRules $rules;

	protected function setUp(): void {
		parent::setUp();
		$rule = new class implements ISessionStateRule {
			public function check(SessionState $state, RequestTarget $target): ?SessionBlock {
				return SessionBlock::rateLimited('directory_rate_limited', 'Too many requests of this kind. Try again later.', 240);
			}
		};
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturn($rule);
		$this->rules = new class($container, $this->createMock(LoggerInterface::class)) extends SessionStateRules {
			protected function classes(): array {
				return [ISessionStateRule::class];
			}
		};
	}

	public function testABlockKnowsItIsARateLimit(): void {
		$block = SessionBlock::rateLimited('x', 'y', 0);
		$this->assertTrue($block->isRateLimit());
		$this->assertSame(1, $block->retryAfter, 'Never 0 seconds');
		$this->assertFalse((new SessionBlock('x', 'X-Header', 'y'))->isRateLimit());
	}

	public function testAScriptGetsJsonWith429(): void {
		$middleware = $this->middleware();
		$controller = $this->createMock(Controller::class);
		$response = $middleware->afterException($controller, 'index', $this->blocked($middleware, $controller));
		$this->assertInstanceOf(JSONResponse::class, $response);
		$this->assertSame(Http::STATUS_TOO_MANY_REQUESTS, $response->getStatus());
		$this->assertSame(['error' => 'directory_rate_limited'], $response->getData());
		$this->assertSame('240', $response->getHeaders()['Retry-After'] ?? null);
	}

	public function testABrowserGetsTheTooManyRequestsPage(): void {
		$this->accept = 'text/html';
		$middleware = $this->middleware();
		$controller = $this->createMock(Controller::class);
		$response = $middleware->afterException($controller, 'index', $this->blocked($middleware, $controller));
		$this->assertInstanceOf(TooManyRequestsResponse::class, $response);
		$this->assertSame('240', $response->getHeaders()['Retry-After'] ?? null);
	}

	public function testOcsGetsAnOcs429WithRetryAfter(): void {
		$middleware = $this->middleware();
		$controller = $this->createMock(OCSController::class);
		try {
			$middleware->afterException($controller, 'index', $this->blocked($middleware, $controller));
			$this->fail('Core\'s OCS middleware builds the answer');
		} catch (OCSException $e) {
			$this->assertSame(Http::STATUS_TOO_MANY_REQUESTS, $e->getCode());
		}
		// The response core builds then gets the header.
		$response = $middleware->afterController($controller, 'index', new DataResponse([], Http::STATUS_TOO_MANY_REQUESTS));
		$this->assertSame('240', $response->getHeaders()['Retry-After'] ?? null);
	}

	public function testOtherResponsesGetNoRetryAfter(): void {
		$response = $this->middleware()->afterController($this->createMock(Controller::class), 'index', new DataResponse([]));
		$this->assertArrayNotHasKey('Retry-After', $response->getHeaders());
	}

	public function testWebDavGets429WithoutAnExceptionToLog(): void {
		$userSession = $this->createMock(IUserSession::class);
		$userSession->method('isLoggedIn')->willReturn(true);
		$plugin = new SessionStatePlugin($this->rules, new SessionState($this->createMock(ISession::class), $this->createMock(LoggerInterface::class)), $userSession, $this->createMock(LoggerInterface::class));
		$request = $this->createMock(RequestInterface::class);
		$request->method('getMethod')->willReturn('REPORT');
		$request->method('getUrl')->willReturn('/remote.php/dav/principals/users/');
		$response = new Response();
		$this->assertFalse($plugin->beforeMethod($request, $response), 'Sabre stops and sends the response');
		$this->assertSame(429, $response->getStatus());
		$this->assertSame('240', $response->getHeader('Retry-After'));
		$this->assertSame('Too many requests of this kind. Try again later.', $response->getBodyAsString());
	}

	private function blocked(SessionStateMiddleware $middleware, Controller $controller): SessionBlockedException {
		try {
			$middleware->beforeController($controller, 'index');
		} catch (SessionBlockedException $e) {
			return $e;
		}
		$this->fail('The rule blocks');
	}

	private function middleware(): SessionStateMiddleware {
		$request = $this->createMock(IRequest::class);
		$request->method('getMethod')->willReturn('GET');
		$request->method('getRequestUri')->willReturn('/index.php/u/bob');
		$request->method('getHeader')->willReturnCallback(fn (string $name): string => $name === 'Accept' ? $this->accept : '');
		$userSession = $this->createMock(IUserSession::class);
		$userSession->method('isLoggedIn')->willReturn(true);
		return new SessionStateMiddleware(
			$this->rules,
			new SessionState($this->createMock(ISession::class), $this->createMock(LoggerInterface::class)),
			$userSession,
			$request,
			$this->createMock(LoggerInterface::class),
		);
	}
}
