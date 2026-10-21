<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\TrapUrl;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Event\TypedEvents;
use OCA\IntrusionDetection\Guard\TrapUrlGuard;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\Handlers\BanHandler;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IAppConfig;
use OCP\IConfig;
use OCP\IRequest;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

#[Group('DB')]
class TrapUrlGuardTest extends IntegrationTestCase {
	private Settings $settings;
	private DetectionMapper $detections;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = Server::get(Settings::class);
		$this->detections = Server::get(DetectionMapper::class);
	}

	public function testATrapPathIsAnsweredWithTheBlocksReference(): void {
		$decision = $this->guard()->check($this->request('/wp-login.php?x=1'));
		$this->assertNotNull($decision);
		$ban = Server::get(BanMapper::class)->findActiveForKeys(['198.51.100.7'], time())[0];
		$this->assertSame($ban->getDisplayReference(), $decision->getReference());
		$this->assertEqualsWithDelta(14400, $decision->getRetryAfter(), 5);

		$detection = $this->detections->findList(new DetectionFilter(checkIds: [TrapUrl::ID]))[0];
		$this->assertSame('/wp-login.php', $detection->getExplanationData()['facts']['path']);
		$this->assertSame('GET', $detection->getExplanationData()['facts']['method']);
	}

	public function testHitsFromOneSourceAreMergedWithinTheHour(): void {
		$this->settings->setMode(TrapUrl::ID, Mode::Observe);
		$guard = $this->guard();
		$this->assertNull($guard->check($this->request('/.env')));
		$this->assertNull($guard->check($this->request('/.git/config')));
		$detections = $this->detections->findList(new DetectionFilter(checkIds: [TrapUrl::ID]));
		$this->assertCount(1, $detections);
		$this->assertSame(2, $detections[0]->getHits());
		$this->assertFalse($detections[0]->isEnforced());
		$this->assertSame(0, Server::get(BanMapper::class)->countActive(time()));
	}

	public function testNormalPathsPassWithoutTouchingTheDatabase(): void {
		$container = $this->createMock(ContainerInterface::class);
		$container->expects($this->never())->method('get');
		$guard = $this->guard($container);
		foreach (['/', '/login', '/apps/files/', '/remote.php/dav/files/alice/.env', '/status.php', '/.well-known/caldav'] as $path) {
			$this->assertNull($guard->check($this->request($path)), $path);
		}
	}

	public function testRequestsWithCredentialsAreNeverChecked(): void {
		$guard = $this->guard();
		$this->assertNull($guard->check($this->request('/wp-login.php', headers: ['Authorization' => 'Basic YWxpY2U6c2VjcmV0'])));
		$this->assertNull($guard->check($this->request('/wp-login.php', cookies: ['nc_session_id' => 'x'])));
		$this->assertNull($guard->check($this->request('/wp-login.php', cookies: ['nc_token' => 'x'])));
		$instanceId = Server::get(IConfig::class)->getSystemValueString('instanceid');
		$this->assertNull($guard->check($this->request('/wp-login.php', cookies: [$instanceId => 'x'])));
		$this->assertSame(0, $this->detections->count(new DetectionFilter()));
	}

	public function testCustomPathsAndTheirValidation(): void {
		$this->settings->setParam(TrapUrl::ID, 'paths', ['/Old-Admin', '/backup/*']);
		$this->assertSame(['/old-admin', '/backup/*'], $this->settings->paramList(TrapUrl::ID, 'paths'));
		$this->assertNotNull($this->guard()->check($this->request('/backup/db.sql', ip: '198.51.100.8')));
		$this->assertNotNull($this->guard()->check($this->request('/OLD-ADMIN', ip: '198.51.100.9')));

		$this->expectException(InvalidParamException::class);
		$this->settings->setParam(TrapUrl::ID, 'paths', ['/apps/*']);
	}

	public function testTheBuiltInListCanBeSwitchedOff(): void {
		$this->settings->setParam(TrapUrl::ID, 'builtin_enabled', false);
		$this->assertNull($this->guard()->check($this->request('/wp-login.php')));
		$this->assertSame(0, $this->detections->count(new DetectionFilter()));
	}

	public function testACustomPathCoveringABuiltInOneStillFiresWithTheBuiltInListOff(): void {
		$this->settings->setParam(TrapUrl::ID, 'builtin_enabled', false);
		$this->settings->setParam(TrapUrl::ID, 'paths', ['/wp-login.php']);
		$this->assertNotNull($this->guard()->check($this->request('/wp-login.php')));
		$detection = $this->detections->findList(new DetectionFilter(checkIds: [TrapUrl::ID]))[0];
		$this->assertSame('/wp-login.php', $detection->getExplanationData()['facts']['trap']);
		$this->assertNull($this->guard()->check($this->request('/.env', ip: '198.51.100.8')), 'Other built-in paths stay off');
	}

	public function testALureFromAnotherSiteIsRecordedButNotBlocked(): void {
		$headers = ['Sec-Fetch-Site' => 'cross-site', 'Sec-Fetch-Mode' => 'no-cors', 'Sec-Fetch-Dest' => 'image'];
		$request = $this->request('/.env', headers: $headers);
		$this->assertNull($this->guard(request: $request)->check($request));
		$this->assertSame(0, Server::get(BanMapper::class)->countActive(time()));
		$detection = $this->detections->findList(new DetectionFilter(checkIds: [TrapUrl::ID]))[0];
		$this->assertTrue($detection->isEnforced());
		$this->assertSame(ResponseOutcome::NOTE_HELD_BACK, $detection->getActionList()[0]['note']);

		// The same address without fetch metadata, as a scanner sends it, is blocked.
		$scanner = $this->request('/.git/config');
		$this->assertNotNull($this->guard(request: $scanner)->check($scanner));
	}

	public function testOffAndTheMasterSwitchSkipTheCheck(): void {
		$this->settings->setMode(TrapUrl::ID, Mode::Off);
		$this->assertNull($this->guard()->check($this->request('/wp-login.php')));
		$this->settings->setMode(TrapUrl::ID, Mode::Protect);
		$this->settings->setGlobal('protection_enabled', false);
		$this->assertNull($this->guard()->check($this->request('/wp-login.php')));
		$this->assertSame(0, $this->detections->count(new DetectionFilter()));
	}

	public function testLoopbackIsIgnored(): void {
		$this->assertNull($this->guard()->check($this->request('/wp-login.php', ip: '127.0.0.1')));
		$this->assertSame(0, $this->detections->count(new DetectionFilter()));
	}

	public function testAWebRootIsStripped(): void {
		$this->assertNotNull($this->guard()->check($this->request('/nextcloud/index.php/.env', script: '/nextcloud/index.php')));
	}

	/**
	 * @param ?IRequest $request the request the responses see, when they read it
	 */
	private function guard(?ContainerInterface $container = null, ?IRequest $request = null): TrapUrlGuard {
		return new TrapUrlGuard(
			Server::get(IConfig::class),
			Server::get(IAppConfig::class),
			$this->settings,
			new RemoteAddressResolver($this->createMock(IRequest::class), Server::get(IThrottler::class)),
			Server::get(ITimeFactory::class),
			$container ?? $this->container($request),
			Server::get(GuardTimer::class),
		);
	}

	private function container(?IRequest $request): ContainerInterface {
		$engine = $request === null ? Server::get(ResponseEngine::class) : new ResponseEngine(
			Server::get(CheckRegistry::class),
			$this->settings,
			Server::get(DetectionService::class),
			new OverridingContainer([BanHandler::class => new BanHandler(
				Server::get(BanService::class),
				Server::get(ContainerInterface::class),
				$request,
				new RemoteAddressResolver($request, Server::get(IThrottler::class)),
			)]),
			Server::get(TypedEvents::class),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
		);
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $id): object => match ($id) {
			ResponseEngine::class => $engine,
			AddressResolver::class => Server::get(AddressResolver::class),
		});
		return $container;
	}

	/**
	 * @param array<string, string> $headers
	 * @param array<string, string> $cookies
	 */
	private function request(string $uri, array $headers = [], array $cookies = [], string $ip = '198.51.100.7', string $script = '/index.php'): IRequest {
		$request = $this->createMock(IRequest::class);
		$request->method('getRequestUri')->willReturn($uri);
		$request->method('getScriptName')->willReturn($script);
		$request->method('getRemoteAddress')->willReturn($ip);
		$request->method('getMethod')->willReturn('GET');
		$request->method('getHeader')->willReturnCallback(static fn (string $name): string => $headers[$name] ?? '');
		$request->method('getCookie')->willReturnCallback(static fn (string $name): ?string => $cookies[$name] ?? null);
		return $request;
	}
}
