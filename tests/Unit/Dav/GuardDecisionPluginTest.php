<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Dav;

use OCA\IntrusionDetection\Dav\GuardDecisionPlugin;
use OCA\IntrusionDetection\Guard\DeferredHits;
use OCA\IntrusionDetection\Guard\IDeferredResponder;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Traps\TrapResponder;
use OCP\IUser;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Security\Guard\GuardDecision;
use OCP\Server;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Sabre\DAV\Server as SabreServer;
use Sabre\HTTP\Request;
use Sabre\HTTP\Response;
use Sabre\HTTP\ResponseInterface;
use Sabre\HTTP\Sapi;
use Test\TestCase;

class GuardDecisionPluginTest extends TestCase {
	public function testARequestWithoutAHitPassesAndLoadsNothing(): void {
		$container = $this->createMock(ContainerInterface::class);
		$container->expects($this->never())->method('get');
		$plugin = new GuardDecisionPlugin(new RequestContext(), $container, $this->createMock(LoggerInterface::class));
		$this->assertTrue($plugin->beforeMethod(new Request('PROPFIND', '/remote.php/dav/files/alice/'), new Response()));
	}

	public function testAHitDecidedAtTheLoginIsRefused(): void {
		$context = new RequestContext();
		$context->refuse(GuardDecision::deny(3600, 'BAAA-AAAB'));
		$response = new Response();
		$plugin = new GuardDecisionPlugin($context, $this->container($context, null), $this->createMock(LoggerInterface::class));
		$sapi = new class extends Sapi {
			/** @var list<ResponseInterface> */
			public static array $sent = [];

			public static function sendResponse(ResponseInterface $response): void {
				self::$sent[] = $response;
			}
		};
		$plugin->initialize(new SabreServer(null, $sapi));
		$this->assertFalse($plugin->beforeMethod(new Request('PROPFIND', '/remote.php/dav/files/alice/'), $response), 'Sabre stops');
		$this->assertSame([$response], $sapi::$sent, 'and the answer is sent, which Sabre does not do for a stopped method');
		$this->assertSame(403, $response->getStatus());
		$this->assertSame('3600', $response->getHeader('Retry-After'));
		$this->assertStringContainsString('BAAA-AAAB', (string)$response->getBodyAsString());
	}

	public function testAHitOfARequestLoggedInByItsSessionIsDecidedHere(): void {
		$context = new RequestContext();
		$context->set(TrapResponder::CONTEXT_KEY, 'waiting');
		$user = $this->createMock(IUser::class);
		$responder = $this->createMock(IDeferredResponder::class);
		$responder->expects($this->once())->method('resolve')->with($user)->willReturnCallback(static function () use ($context): GuardDecision {
			$decision = GuardDecision::deny(60, 'BAAA-AAAC');
			$context->refuse($decision);
			return $decision;
		});
		$response = new Response();
		$plugin = new GuardDecisionPlugin($context, $this->container($context, $user, $responder), $this->createMock(LoggerInterface::class));
		$this->assertFalse($plugin->beforeMethod(new Request('GET', '/remote.php/dav/files/alice/x'), $response));
		$this->assertSame(403, $response->getStatus());
	}

	public function testAFailureLetsTheRequestThrough(): void {
		$context = new RequestContext();
		$context->set(TrapResponder::CONTEXT_KEY, 'waiting');
		$responder = $this->createMock(IDeferredResponder::class);
		$responder->method('resolve')->willThrowException(new \RuntimeException('database gone'));
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error');
		$plugin = new GuardDecisionPlugin($context, $this->container($context, null, $responder), $logger);
		$this->assertTrue($plugin->beforeMethod(new Request('GET', '/remote.php/dav/files/alice/x'), new Response()));
	}

	private function container(RequestContext $context, ?IUser $user, ?IDeferredResponder $responder = null): ContainerInterface {
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturn($user);
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static function (string $class) use ($context, $session, $responder, &$container): mixed {
			return match ($class) {
				DeferredHits::class => new DeferredHits($context, $container),
				IUserSession::class => $session,
				TrapResponder::class => $responder,
				IFactory::class => Server::get(IFactory::class),
			};
		});
		return $container;
	}
}
