<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\Check\Checks\TrapUrl\TrapResponder;
use OCA\IntrusionDetection\Check\Checks\TrapUrl\TrapUrl;
use OCA\IntrusionDetection\Check\Checks\TrapUrl\TrapUrlFacts;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Guard\DeferredHits;
use OCA\IntrusionDetection\Guard\TrapUrlGuard;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Middleware\PayloadBlockedException;
use OCA\IntrusionDetection\Middleware\PayloadMiddleware;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IAppConfig;
use OCP\IConfig;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserSession;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

#[Group('DB')]
class TrapUrlGuardTest extends IntegrationTestCase {
	/** What a browser sends for an image another site embeds */
	private const LURE = ['Sec-Fetch-Site' => 'cross-site', 'Sec-Fetch-Mode' => 'no-cors', 'Sec-Fetch-Dest' => 'image'];

	private DetectionMapper $detections;
	private RequestContext $context;
	private TrapResponder $responder;
	/** @var list<\Closure> */
	private array $shutdown = [];
	private ?IUser $sessionUser = null;

	protected function setUp(): void {
		parent::setUp();
		$this->detections = Server::get(DetectionMapper::class);
		$this->context = new RequestContext();
		$shutdown = &$this->shutdown;
		$this->responder = new class(Server::get(ResponseEngine::class), Server::get(AddressResolver::class), $this->context, Server::get(ITimeFactory::class), $this->container(), Server::get(LoggerInterface::class), $shutdown) extends TrapResponder {
			/** @param list<\Closure> $shutdown */
			public function __construct(
				ResponseEngine $engine,
				AddressResolver $resolver,
				RequestContext $context,
				ITimeFactory $time,
				ContainerInterface $container,
				LoggerInterface $logger,
				private array &$shutdown,
			) {
				parent::__construct($engine, $resolver, $context, $time, $container, $logger);
			}

			protected function registerShutdown(\Closure $callback): void {
				$this->shutdown[] = $callback;
			}
		};
	}

	public function testATrapPathIsAnsweredWithTheBlocksReference(): void {
		$decision = $this->guard()->check($this->request('/wp-login.php?x=1'));
		$this->assertNotNull($decision);
		$ban = Server::get(BanMapper::class)->findActiveForKeys(['198.51.100.7'], time())[0];
		$this->assertSame($ban->getDisplayReference(), $decision->getReference());
		$this->assertEqualsWithDelta(14400, $decision->getRetryAfter(), 5);

		$detection = $this->detections->findList(new DetectionFilter(checkIds: [TrapUrl::ID]))[0];
		$this->assertSame('/wp-login.php', TrapUrlFacts::fromArray($detection->getExplanationData()['facts'])->path);
		$this->assertSame('GET', TrapUrlFacts::fromArray($detection->getExplanationData()['facts'])->method);
	}

	public function testHitsFromOneSourceAreMergedWithinTheHour(): void {
		$this->settingsEditor()->setMode(TrapUrl::ID, Mode::Observe);
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

	/**
	 * @return array<string, array{array<string, string>, array<string, string>}>
	 */
	public static function credentials(): array {
		$instanceId = Server::get(IConfig::class)->getSystemValueString('instanceid');
		return [
			'Basic' => [['Authorization' => 'Basic YWxpY2U6c2VjcmV0'], []],
			'Bearer' => [['Authorization' => 'Bearer x'], []],
			'a session cookie' => [[], [$instanceId => 'x']],
			'a remember-me cookie' => [[], ['nc_token' => 'x']],
			'a cookie a scanner made up' => [[], ['nc_username' => 'x']],
		];
	}

	/**
	 * @param array<string, string> $headers
	 * @param array<string, string> $cookies
	 */
	#[DataProvider('credentials')]
	public function testAHitWithCredentialsWaitsForTheLoginAndLoggedInUsersNeverTripIt(array $headers, array $cookies): void {
		$this->assertNull($this->guard()->check($this->request('/wp-login.php', headers: $headers, cookies: $cookies)));
		$this->assertSame(0, $this->detections->count(new DetectionFilter()), 'Nothing is decided yet');
		$this->assertTrue(DeferredHits::isPending($this->context));
		$this->sessionUser = $this->createMock(IUser::class);
		$this->assertNull((new DeferredHits($this->context, $this->container()))->resolve($this->sessionUser));
		$this->assertFalse(DeferredHits::isPending($this->context));
		$this->assertSame(0, $this->detections->count(new DetectionFilter()), 'A logged-in request never trips it');
	}

	/**
	 * @param array<string, string> $headers
	 * @param array<string, string> $cookies
	 */
	#[DataProvider('credentials')]
	public function testAHitWithCredentialsThatDoNotLogInIsATrapHit(array $headers, array $cookies): void {
		$this->assertNull($this->guard()->check($this->request('/wp-login.php', headers: $headers, cookies: $cookies)));
		$this->assertCount(1, $this->shutdown, 'Decided at the end of the request at the latest');
		($this->shutdown[0])();
		$this->assertSame(1, $this->detections->count(new DetectionFilter(checkIds: [TrapUrl::ID])));
		$this->assertCount(1, Server::get(BanMapper::class)->findActiveForKeys(['198.51.100.7'], time()));
		$this->assertNotNull($this->context->refusal(), 'Later steps of the request refuse it');
	}

	public function testTheMiddlewareRefusesATrapHitWithMadeUpCredentialsBeforeTheController(): void {
		$this->guard()->check($this->request('/wp-login.php', cookies: ['nc_username' => 'x']));
		$middleware = new PayloadMiddleware($this->context, $this->container(), Server::get(LoggerInterface::class));
		$this->expectException(PayloadBlockedException::class);
		$middleware->beforeController($this->createMock(Controller::class), 'index');
	}

	public function testCustomPathsAndTheirValidation(): void {
		$this->settingsEditor()->setParam(TrapUrl::ID, 'paths', ['/Old-Admin', '/backup/*']);
		$this->assertSame(['/old-admin', '/backup/*'], $this->checkSettings()->paramList(TrapUrl::ID, 'paths'));
		$this->assertNotNull($this->guard()->check($this->request('/backup/db.sql', ip: '198.51.100.8')));
		$this->assertNotNull($this->guard()->check($this->request('/OLD-ADMIN', ip: '198.51.100.9')));

		$this->expectException(InvalidParamException::class);
		$this->settingsEditor()->setParam(TrapUrl::ID, 'paths', ['/apps/*']);
	}

	public function testTheBuiltInListCanBeSwitchedOff(): void {
		$this->settingsEditor()->setParam(TrapUrl::ID, 'builtin_enabled', false);
		$this->assertNull($this->guard()->check($this->request('/wp-login.php')));
		$this->assertSame(0, $this->detections->count(new DetectionFilter()));
	}

	public function testACustomPathCoveringABuiltInOneStillFiresWithTheBuiltInListOff(): void {
		$this->settingsEditor()->setParam(TrapUrl::ID, 'builtin_enabled', false);
		$this->settingsEditor()->setParam(TrapUrl::ID, 'paths', ['/wp-login.php']);
		$this->assertNotNull($this->guard()->check($this->request('/wp-login.php')));
		$detection = $this->detections->findList(new DetectionFilter(checkIds: [TrapUrl::ID]))[0];
		$this->assertSame('/wp-login.php', TrapUrlFacts::fromArray($detection->getExplanationData()['facts'])->trap);
		$this->assertNull($this->guard()->check($this->request('/.env', ip: '198.51.100.8')), 'Other built-in paths stay off');
	}

	public function testALureFromAnotherSiteIsRecordedButNotBlocked(): void {
		$this->assertNull($this->guard()->check($this->request('/.env', headers: self::LURE)));
		$this->assertSame(0, Server::get(BanMapper::class)->countActive(time()));
		$detection = $this->detections->findList(new DetectionFilter(checkIds: [TrapUrl::ID]))[0];
		$this->assertTrue($detection->isEnforced());
		$this->assertSame(ResponseOutcome::NOTE_HELD_BACK, $detection->getActionList()[0]['note']);

		// The same address without fetch metadata, as a scanner sends it, is blocked.
		$this->assertNotNull($this->guard()->check($this->request('/.git/config')));
	}

	public function testOnlyAGetOrHeadRequestCanBeALure(): void {
		$this->assertNotNull($this->guard()->check($this->request('/.env', headers: self::LURE, method: 'POST')));
	}

	public function testARequestFromAPageOfThisServerIsNoLure(): void {
		$headers = self::LURE + ['Referer' => 'https://cloud.example.com/index.php/apps/files/'];
		$this->assertNotNull($this->guard()->check($this->request('/.env', headers: $headers)));
	}

	public function testOffAndTheMasterSwitchSkipTheCheck(): void {
		$this->settingsEditor()->setMode(TrapUrl::ID, Mode::Off);
		$this->assertNull($this->guard()->check($this->request('/wp-login.php')));
		$this->settingsEditor()->setMode(TrapUrl::ID, Mode::Protect);
		$this->settingsEditor()->setGlobal('protection_enabled', false);
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

	private function guard(?ContainerInterface $container = null): TrapUrlGuard {
		return new TrapUrlGuard(
			Server::get(IConfig::class),
			Server::get(IAppConfig::class),
			$this->appSettings(), $this->checkSettings(),
			new RemoteAddressResolver($this->createMock(IRequest::class), Server::get(IThrottler::class), Server::get(ServerAddresses::class)),
			$container ?? $this->container(),
			Server::get(GuardTimer::class),
		);
	}

	/**
	 * The app container as the guard sees it, with the test's request
	 * context, responder and session.
	 */
	private function container(): ContainerInterface {
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(function (string $id) use ($container): object {
			return match ($id) {
				TrapResponder::class => $this->responder,
				DeferredHits::class => new DeferredHits($this->context, $container),
				IUserSession::class => $this->userSession(),
				default => Server::get($id),
			};
		});
		return $container;
	}

	private function userSession(): IUserSession {
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturnCallback(fn (): ?IUser => $this->sessionUser);
		return $session;
	}

	/**
	 * @param array<string, string> $headers
	 * @param array<string, string> $cookies
	 */
	private function request(string $uri, array $headers = [], array $cookies = [], string $ip = '198.51.100.7', string $script = '/index.php', string $method = 'GET'): IRequest {
		$request = $this->createMock(IRequest::class);
		$request->method('getRequestUri')->willReturn($uri);
		$request->method('getScriptName')->willReturn($script);
		$request->method('getRemoteAddress')->willReturn($ip);
		$request->method('getMethod')->willReturn($method);
		$request->method('getServerHost')->willReturn('cloud.example.com');
		$request->method('getHeader')->willReturnCallback(static fn (string $name): string => $headers[$name] ?? '');
		$request->method('getCookie')->willReturnCallback(static fn (string $name): ?string => $cookies[$name] ?? null);
		return $request;
	}
}
