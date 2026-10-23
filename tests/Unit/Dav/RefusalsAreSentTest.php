<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Dav;

use OCA\IntrusionDetection\Dav\GuardDecisionPlugin;
use OCA\IntrusionDetection\Dav\SessionStatePlugin;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\SessionState\SessionStateRules;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Security\Guard\GuardDecision;
use OCP\Server;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Sabre\DAV\Server as SabreServer;
use Sabre\HTTP\Request;
use Sabre\HTTP\ResponseInterface;
use Sabre\HTTP\Sapi;
use Test\TestCase;

/**
 * The refusals of the WebDAV plugins reach the client through Sabre's own
 * request handling: a listener that stops a method must send the answer,
 * since Sabre then sends none (an empty 200 otherwise).
 */
class RefusalsAreSentTest extends TestCase {
	/** @var list<array{status: int, headers: array<string, string>, body: string}> */
	private static array $sent = [];

	protected function setUp(): void {
		parent::setUp();
		self::$sent = [];
	}

	private function server(string $method, string $url): SabreServer {
		$sapi = new class extends Sapi {
			public static function sendResponse(ResponseInterface $response): void {
				RefusalsAreSentTest::record($response);
			}
		};
		$server = new SabreServer(null, $sapi);
		$server->setBaseUri('/remote.php/dav/');
		$server->httpRequest = new Request($method, $url);
		return $server;
	}

	public static function record(ResponseInterface $response): void {
		$headers = [];
		foreach (array_keys($response->getHeaders()) as $name) {
			$headers[strtolower((string)$name)] = (string)$response->getHeader((string)$name);
		}
		self::$sent[] = ['status' => $response->getStatus(), 'headers' => $headers, 'body' => (string)$response->getBodyAsString()];
	}

	public function testARateLimitOfTheSessionRulesIsSentWithItsBodyAndRetryAfter(): void {
		$server = $this->server('REPORT', '/remote.php/dav/principals/users/');
		$server->addPlugin($this->sessionStatePlugin(SessionBlock::rateLimited('directory_rate_limited', 'Too many requests of this kind. Try again later.', 240)));
		$server->start();
		$this->assertCount(1, self::$sent, 'one answer');
		$this->assertSame(429, self::$sent[0]['status']);
		$this->assertSame('240', self::$sent[0]['headers']['retry-after'] ?? null);
		$this->assertSame('Too many requests of this kind. Try again later.', self::$sent[0]['body']);
	}

	public function testABlockOfTheSessionRulesIsSentAsForbiddenWithItsHeader(): void {
		$server = $this->server('PROPFIND', '/remote.php/dav/files/alice/');
		$server->addPlugin($this->sessionStatePlugin(new SessionBlock('password_change_required', 'X-Nextcloud-Password-Change', 'Choose a new password first.')));
		$server->start();
		$this->assertCount(1, self::$sent);
		$this->assertSame(403, self::$sent[0]['status']);
		$this->assertSame('required', self::$sent[0]['headers']['x-nextcloud-password-change'] ?? null);
		$this->assertStringContainsString('Choose a new password first.', self::$sent[0]['body']);
	}

	public function testARefusedGuardHitIsSentOnceAndTheSessionRulesDoNotRun(): void {
		$context = new RequestContext();
		$context->refuse(GuardDecision::deny(3600, 'BAAA-AAAB'));
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $class): mixed => $class === IFactory::class ? Server::get(IFactory::class) : null);
		$server = $this->server('PROPFIND', '/remote.php/dav/files/alice/');
		$server->addPlugin(new GuardDecisionPlugin($context, $container, $this->createMock(LoggerInterface::class)));
		$server->addPlugin($this->sessionStatePlugin(SessionBlock::rateLimited('directory_rate_limited', 'not this one', 1)));
		$server->start();
		$this->assertCount(1, self::$sent);
		$this->assertSame(403, self::$sent[0]['status']);
		$this->assertSame('3600', self::$sent[0]['headers']['retry-after'] ?? null);
		$this->assertStringContainsString('BAAA-AAAB', self::$sent[0]['body']);
	}

	private function sessionStatePlugin(SessionBlock $block): SessionStatePlugin {
		$rule = new class($block) implements ISessionStateRule {
			public function __construct(
				private readonly SessionBlock $block,
			) {
			}

			public function check(SessionState $state, RequestTarget $target): ?SessionBlock {
				return $this->block;
			}
		};
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturn($rule);
		$rules = new class($container, $this->createMock(LoggerInterface::class), new RequestContext(), $this->createMock(IRequest::class)) extends SessionStateRules {
			protected function classes(): array {
				return [ISessionStateRule::class];
			}
		};
		$userSession = $this->createMock(IUserSession::class);
		$userSession->method('isLoggedIn')->willReturn(true);
		return new SessionStatePlugin($rules, new SessionState($this->createMock(ISession::class), $this->createMock(LoggerInterface::class)), $userSession, $this->createMock(LoggerInterface::class));
	}
}
