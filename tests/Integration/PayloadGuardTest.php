<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\AppFramework\Http\Request;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\CustomSignatures;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\FormMatch;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\InjectionProbe;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\InjectionProbeFacts;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PayloadInspector;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PayloadResponder;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PayloadSettings;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PendingHit;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\RequestParts;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Guard\AddressGuard;
use OCA\IntrusionDetection\Guard\DeferredHits;
use OCA\IntrusionDetection\Guard\PayloadGuard;
use OCA\IntrusionDetection\Listener\PayloadLoginListener;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Middleware\PayloadBlockedException;
use OCA\IntrusionDetection\Middleware\PayloadMiddleware;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\OCSController;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IConfig;
use OCP\IRequest;
use OCP\IRequestId;
use OCP\IUser;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Security\Guard\GuardDecision;
use OCP\Server;
use OCP\User\Events\UserLoggedInEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The injection probe check end to end: the guard, the matcher, the
 * response engine, the database, and the paths that resolve requests with
 * credentials.
 */
#[Group('DB')]
class PayloadGuardTest extends IntegrationTestCase {
	private const IP = '198.51.100.23';

	private RequestContext $context;
	/** @var list<\Closure> */
	private array $shutdown = [];
	private ?IUser $sessionUser = null;
	private PayloadResponder $responder;

	protected function setUp(): void {
		parent::setUp();
		$this->context = new RequestContext();
		$shutdown = &$this->shutdown;
		$this->responder = new class(Server::get(ResponseEngine::class), Server::get(PayloadSettings::class), $this->context, Server::get(ITimeFactory::class), $this->container(), Server::get(LoggerInterface::class), $shutdown) extends PayloadResponder {
			/** @param list<\Closure> $shutdown */
			public function __construct(
				ResponseEngine $engine,
				PayloadSettings $settings,
				RequestContext $context,
				ITimeFactory $time,
				ContainerInterface $container,
				LoggerInterface $logger,
				private array &$shutdown,
			) {
				parent::__construct($engine, $settings, $context, $time, $container, $logger);
			}

			protected function registerShutdown(\Closure $callback): void {
				$this->shutdown[] = $callback;
			}
		};
	}

	/**
	 * @return array<string, array{0: string, 1: string, 2: array<string, string>}>
	 */
	public static function mustFire(): array {
		return PayloadCorpus::mustFire();
	}

	/**
	 * @return array<string, array{0: string, 1: string, 2: array<string, string>}>
	 */
	public static function mustNotFire(): array {
		return PayloadCorpus::mustNotFire();
	}

	/**
	 * @param array<string, string> $post
	 */
	#[DataProvider('mustFire')]
	public function testMustFire(string $uri, string $script, array $post): void {
		$decision = $this->decide($uri, $script, $post);

		$this->assertNotNull($decision, 'The request is refused');
		$bans = Server::get(BanMapper::class)->findActiveForKeys([self::IP], time());
		$this->assertCount(1, $bans);
		$this->assertSame($bans[0]->getDisplayReference(), $decision->getReference());
		$this->assertEqualsWithDelta(14400, $decision->getRetryAfter(), 5);

		$detection = $this->onlyDetection();
		$this->assertTrue($detection->isEnforced());
		$this->assertSame(self::IP, $detection->getIp());
		$this->assertNull($detection->getUid());
		$facts = InjectionProbeFacts::fromArray($detection->getExplanationData()['facts']);
		$this->assertFalse($facts->authenticated);
		$this->assertNotSame([], $facts->signatures);
		$this->assertGreaterThanOrEqual(3, $facts->weight);
		$this->assertLessThanOrEqual(200, mb_strlen($facts->excerpt));
		$this->assertSame('sqlmap/1.7', $detection->getExplanationData()['userAgent']);
		$this->assertSame('ban', $detection->getActionList()[0]['type']);
	}

	/**
	 * @param array<string, string> $post
	 */
	#[DataProvider('mustNotFire')]
	public function testMustNotFire(string $uri, string $script, array $post): void {
		$this->assertNull($this->decide($uri, $script, $post));
		$this->assertSame([], $this->detections());
		$this->assertSame([], Server::get(BanMapper::class)->findActiveForKeys([self::IP], time()));
	}

	/**
	 * Logged-in users are only observed: a detection naming them, no block.
	 *
	 * @param array<string, string> $post
	 */
	#[DataProvider('mustFire')]
	public function testMustFireWithASessionCookieIsOnlyObserved(string $uri, string $script, array $post): void {
		$this->assertNull($this->decide($uri, $script, $post, [$this->sessionCookie() => 'abc']));
		$this->assertTrue($this->responder->hasPending());
		$this->assertSame([], $this->detections(), 'Nothing is recorded before the user is known');

		$this->assertNull($this->responder->resolve($this->user('alice')));

		$detection = $this->onlyDetection();
		$this->assertFalse($detection->isEnforced());
		$this->assertSame('alice', $detection->getUid());
		$facts = InjectionProbeFacts::fromArray($detection->getExplanationData()['facts']);
		$this->assertTrue($facts->authenticated);
		$this->assertSame(PendingHit::CREDENTIAL_SESSION, $facts->credential);
		$this->assertSame([['type' => 'ban', 'enforced' => false]], $detection->getActionList());
		$this->assertSame([], Server::get(BanMapper::class)->findActiveForKeys([self::IP], time()));
		$this->assertFalse($this->responder->hasPending());
	}

	/**
	 * @param array<string, string> $post
	 */
	#[DataProvider('mustFire')]
	public function testMustFireFromTheBypassListIsIgnored(string $uri, string $script, array $post): void {
		$throttler = $this->createMock(IThrottler::class);
		$throttler->method('isBypassListed')->with(self::IP)->willReturn(true);
		$inspector = $this->createMock(PayloadInspector::class);
		$inspector->expects($this->never())->method('inspect');

		$this->assertNull($this->decide($uri, $script, $post, throttler: $throttler, inspector: $inspector));
		$this->assertSame([], $this->detections());
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function withoutTriggers(): array {
		return [
			'files' => ['/index.php/apps/files/'],
			'notifications' => ['/ocs/v2.php/apps/notifications/api/v2/notifications?format=json'],
			'preview' => ['/index.php/core/preview?fileId=12345&x=32&y=32&a=1'],
			'redirect' => ['/index.php/login?redirect_url=%2Fapps%2Ffiles%2F'],
			'WebDAV with a quote in the file name' => ['/remote.php/dav/files/alice/Bob\'s%20union%20select.txt'],
		];
	}

	#[DataProvider('withoutTriggers')]
	public function testRequestsWithoutTriggersNeverReachTheMatcher(string $uri): void {
		$container = $this->createMock(ContainerInterface::class);
		$container->expects($this->never())->method('get');
		$guard = new PayloadGuard(Server::get(IConfig::class), $this->addresses(), $container, Server::get(LoggerInterface::class), Server::get(GuardTimer::class));

		$script = str_starts_with($uri, '/remote.php') ? '/remote.php' : (str_starts_with($uri, '/ocs/') ? '/ocs/v2.php' : '/index.php');
		$this->assertNull($guard->check($this->request($uri, $script)));
	}

	public function testAPayloadAfterTheByteLimitIsNotSeenAndDoesNotSlowTheRequest(): void {
		$filler = str_repeat('a', 8192);
		$this->assertNull($this->decide('/index.php/apps/foo?x=' . $filler . '&id=1%20UNION%20SELECT%201', '/index.php'));
		$this->assertNull($this->decide('/index.php/apps/foo?id=' . $filler . '%20UNION%20SELECT%201', '/index.php'));
		$this->assertNull($this->decide('/index.php/apps/foo', '/index.php', ['a' => $filler, 'id' => '1 UNION SELECT 1']));

		// A megabyte of suspicious-looking input is still only scanned up to the limits.
		$huge = '/index.php/apps/foo?x=' . str_repeat("'%20or%20", 120000) . '&id=1%20UNION%20SELECT%201';
		$start = hrtime(true);
		$this->assertNull($this->decide($huge, '/index.php'));
		$ms = (hrtime(true) - $start) / 1e6;
		$this->assertLessThan(50, $ms, 'A huge request took ' . round($ms, 1) . ' ms');
		$this->assertSame([], $this->detections());

		$this->assertNotNull($this->decide('/index.php/apps/foo?x=' . substr($filler, 0, 7000) . '&id=1%20UNION%20SELECT%201', '/index.php'), 'Within the limit it is seen');
	}

	public function testAFakeSessionCookieIsTreatedAsNotLoggedInAtTheEndOfTheRequest(): void {
		$this->assertNull($this->decide('/remote.php/dav/files/x?id=1%20UNION%20SELECT%201', '/remote.php', [], [$this->sessionCookie() => 'forged']));
		$this->assertCount(1, $this->shutdown, 'Resolving is scheduled for the end of the request');

		$this->sessionUser = null;
		($this->shutdown[0])();

		$detection = $this->onlyDetection();
		$this->assertTrue($detection->isEnforced());
		$this->assertSame(PendingHit::CREDENTIAL_SESSION, InjectionProbeFacts::fromArray($detection->getExplanationData()['facts'])->credential);
		$this->assertCount(1, Server::get(BanMapper::class)->findActiveForKeys([self::IP], time()));
	}

	public function testTheEndOfTheRequestNamesTheUserOfASession(): void {
		$this->decide('/remote.php/dav/files/alice/x?id=1%20UNION%20SELECT%201', '/remote.php', [], [$this->sessionCookie() => 'abc']);
		$this->sessionUser = $this->user('alice');
		($this->shutdown[0])();
		$this->assertSame('alice', $this->onlyDetection()->getUid());
		$this->assertSame([], Server::get(BanMapper::class)->findActiveForKeys([self::IP], time()));
	}

	public function testShutdownIsRegisteredOncePerRequest(): void {
		$this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php', [], [$this->sessionCookie() => 'abc']);
		$this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%202', '/index.php', [], [$this->sessionCookie() => 'abc']);
		$this->assertCount(1, $this->shutdown);
		($this->shutdown[0])();
		($this->shutdown[0])();
		$this->assertCount(1, $this->detections());
	}

	public function testTheMiddlewareRefusesAForgedSessionBeforeTheControllerRuns(): void {
		$this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php', [], [$this->sessionCookie() => 'forged']);
		$middleware = new PayloadMiddleware($this->context, $this->container(), Server::get(LoggerInterface::class));
		$controller = $this->createMock(Controller::class);
		$this->sessionUser = null;

		try {
			$middleware->beforeController($controller, 'index');
			$this->fail('The controller must not run');
		} catch (PayloadBlockedException $e) {
			$response = $middleware->afterException($controller, 'index', $e);
		}
		$ban = Server::get(BanMapper::class)->findActiveForKeys([self::IP], time())[0];
		$this->assertSame(Http::STATUS_FORBIDDEN, $response->getStatus());
		$this->assertStringContainsString($ban->getDisplayReference(), $response->render());
		$this->assertEqualsWithDelta(14400, (int)$response->getHeaders()['Retry-After'], 5);

		$other = new \RuntimeException('other');
		$this->expectExceptionObject($other);
		$middleware->afterException($controller, 'index', $other);
	}

	public function testOcsKeepsTheReferenceInItsMessage(): void {
		$this->decide('/ocs/v2.php/cloud/capabilities?id=1%20UNION%20SELECT%201', '/ocs/v2.php', [], [$this->sessionCookie() => 'forged']);
		$middleware = new PayloadMiddleware($this->context, $this->container(), Server::get(LoggerInterface::class));
		$controller = $this->createMock(OCSController::class);
		try {
			$middleware->beforeController($controller, 'index');
			$this->fail('The controller must not run');
		} catch (PayloadBlockedException $e) {
			$response = $middleware->afterException($controller, 'index', $e);
		}
		$this->assertInstanceOf(JSONResponse::class, $response);
		$this->assertSame(Http::STATUS_FORBIDDEN, $response->getStatus());
		$ban = Server::get(BanMapper::class)->findActiveForKeys([self::IP], time())[0];
		$this->assertStringContainsString($ban->getDisplayReference(), $response->getData()['message']);
	}

	public function testTheMiddlewareLetsALoggedInUserThrough(): void {
		$this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php', [], [$this->sessionCookie() => 'abc']);
		$this->sessionUser = $this->user('alice');
		(new PayloadMiddleware($this->context, $this->container(), Server::get(LoggerInterface::class)))->beforeController($this->createMock(Controller::class), 'index');
		$this->assertSame('alice', $this->onlyDetection()->getUid());
	}

	public function testTheMiddlewareCostsNothingWithoutAPendingHit(): void {
		$container = $this->createMock(ContainerInterface::class);
		$container->expects($this->never())->method('get');
		(new PayloadMiddleware(new RequestContext(), $container, Server::get(LoggerInterface::class)))->beforeController($this->createMock(Controller::class), 'index');
	}

	public function testABasicAuthLoginNamesTheUser(): void {
		$this->decide('/remote.php/dav/files/bob?id=1%20UNION%20SELECT%201', '/remote.php', [], [], ['Authorization' => 'Basic ' . base64_encode('bob:app-password')]);
		$listener = new PayloadLoginListener($this->context, $this->container(), Server::get(LoggerInterface::class));
		$listener->handle(new UserLoggedInEvent($this->user('bob'), 'bob', null, false));

		$detection = $this->onlyDetection();
		$this->assertSame('bob', $detection->getUid());
		$this->assertSame(PendingHit::CREDENTIAL_BASIC, InjectionProbeFacts::fromArray($detection->getExplanationData()['facts'])->credential);
		$this->assertFalse($detection->isEnforced());
	}

	public function testAHitDecidedAtTheLoginIsRefusedBeforeTheController(): void {
		$this->settingsEditor()->setParam(InjectionProbe::ID, InjectionProbe::PARAM_AUTHENTICATED_MODE, 'protect');
		$this->decide('/ocs/v2.php/apps/foo?id=1%20UNION%20SELECT%201', '/ocs/v2.php', [], [], ['Authorization' => 'Basic ' . base64_encode('bob:app-password')]);
		(new PayloadLoginListener($this->context, $this->container(), Server::get(LoggerInterface::class)))
			->handle(new UserLoggedInEvent($this->user('bob'), 'bob', null, false));
		$this->assertTrue($this->onlyDetection()->isEnforced());

		$middleware = new PayloadMiddleware($this->context, $this->container(), Server::get(LoggerInterface::class));
		try {
			$middleware->beforeController($this->createMock(Controller::class), 'index');
			$this->fail('The controller must not run');
		} catch (PayloadBlockedException $e) {
			$ban = Server::get(BanMapper::class)->findActiveForKeys([self::IP], time())[0];
			$this->assertSame($ban->getDisplayReference(), $e->decision->getReference());
		}
		$this->assertCount(1, $this->detections(), 'The middleware does not record the hit again');
	}

	public function testAClientsOwnPhpAuthHeaderDoesNotMakeAProbeLoggedIn(): void {
		$decision = $this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%20password%20FROM%20oc_users--', '/index.php', [], [], ['PHP-Auth-User' => 'alice', 'PHP-Auth-Pw' => 'made-up']);
		$this->assertNotNull($decision, 'Still blocked as an anonymous probe');
		$this->assertFalse(InjectionProbeFacts::fromArray($this->onlyDetection()->getExplanationData()['facts'])->authenticated);
	}

	public function testBearerAndRememberMeCountAsCredentials(): void {
		$this->decide('/ocs/v2.php/x?id=1%20UNION%20SELECT%201', '/ocs/v2.php', [], [], ['Authorization' => 'Bearer abc']);
		$this->assertSame(PendingHit::CREDENTIAL_BEARER, $this->context->get(PayloadResponder::CONTEXT_KEY)->credential);
		$this->context->set(PayloadResponder::CONTEXT_KEY, null);
		$this->decide('/index.php/x?id=1%20UNION%20SELECT%201', '/index.php', [], ['nc_token' => 'abc']);
		$this->assertSame(PendingHit::CREDENTIAL_REMEMBER_ME, $this->context->get(PayloadResponder::CONTEXT_KEY)->credential);
	}

	public function testProtectForLoggedInUsersBlocks(): void {
		$this->settingsEditor()->setParam(InjectionProbe::ID, InjectionProbe::PARAM_AUTHENTICATED_MODE, 'protect');
		$this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php', [], [$this->sessionCookie() => 'abc']);
		$decision = $this->responder->resolve($this->user('alice'));
		$this->assertNotNull($decision);
		$this->assertTrue($this->onlyDetection()->isEnforced());
		$this->assertCount(1, Server::get(BanMapper::class)->findActiveForKeys([self::IP], time()));
	}

	public function testLoggedInUsersCanBeIgnored(): void {
		$this->settingsEditor()->setParam(InjectionProbe::ID, InjectionProbe::PARAM_AUTHENTICATED_MODE, 'off');
		$this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php', [], [$this->sessionCookie() => 'abc']);
		$this->assertNull($this->responder->resolve($this->user('alice')));
		$this->assertSame([], $this->detections());

		// The cookie may be forged, so the request is still inspected and decided at the end.
		$this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php', [], [$this->sessionCookie() => 'forged']);
		$this->assertNotNull($this->responder->resolve(null));
	}

	public function testTheChecksModeIsTheCeilingForLoggedInUsers(): void {
		$this->settingsEditor()->setMode(InjectionProbe::ID, Mode::Observe);
		$this->settingsEditor()->setParam(InjectionProbe::ID, InjectionProbe::PARAM_AUTHENTICATED_MODE, 'protect');
		$this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php', [], [$this->sessionCookie() => 'abc']);
		$this->assertNull($this->responder->resolve($this->user('alice')));
		$this->assertFalse($this->onlyDetection()->isEnforced());
	}

	public function testOffDoesNothing(): void {
		$this->settingsEditor()->setMode(InjectionProbe::ID, Mode::Off);
		$inspector = $this->createMock(PayloadInspector::class);
		$inspector->expects($this->never())->method('inspect');
		$this->assertNull($this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php', inspector: $inspector));
		$this->assertNull($this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php', [], [$this->sessionCookie() => 'abc'], inspector: $inspector));
		$this->assertSame([], $this->detections());
	}

	public function testTheMasterSwitchTurnsItOff(): void {
		$this->appConfig->setValueBool(Application::APP_ID, GlobalSettings::ENABLED, false);
		$this->assertNull($this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php'));
		$this->assertSame([], $this->detections());
	}

	public function testTheConfigSwitchTurnsItOff(): void {
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueBool')->with(AddressGuard::DISABLE_SWITCH)->willReturn(true);
		$guard = new PayloadGuard($config, $this->addresses(), $this->container(), Server::get(LoggerInterface::class), Server::get(GuardTimer::class));
		$this->assertNull($guard->check($this->request('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php')));
		$this->assertSame([], $this->detections());
	}

	public function testObserveAndLearningModeDoNotBlock(): void {
		$this->settingsEditor()->setMode(InjectionProbe::ID, Mode::Observe);
		$this->assertNull($this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php'));
		$this->assertFalse($this->onlyDetection()->isEnforced());

		$this->db->getQueryBuilder()->delete('ids_detections')->executeStatement();
		$this->settingsEditor()->setMode(InjectionProbe::ID, Mode::Protect);
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 3600);
		$this->assertNull($this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php'));
		$this->assertSame('learning', $this->onlyDetection()->getExplanationData()['mode']['reason']);
		$this->assertSame([], Server::get(BanMapper::class)->findActiveForKeys([self::IP], time()));
	}

	public function testRepeatedProbesAreMergedAndStayBlocked(): void {
		$first = $this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php');
		$second = $this->decide('/index.php/apps/foo?cat=1%20AND%20SLEEP(5)', '/index.php');
		$this->assertNotNull($first);
		$this->assertNotNull($second);
		$this->assertSame($first->getReference(), $second->getReference());
		$detection = $this->onlyDetection();
		$this->assertSame(2, $detection->getHits());
		$this->assertSame('cat', InjectionProbeFacts::fromArray($detection->getExplanationData()['facts'])->param, 'The latest hit explains the row');
	}

	public function testAProbeInAnImageAnotherSiteEmbedsIsRecordedButNotBlocked(): void {
		$lure = ['Sec-Fetch-Site' => 'cross-site', 'Sec-Fetch-Mode' => 'no-cors', 'Sec-Fetch-Dest' => 'image'];
		$this->assertNull($this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php', headers: $lure));
		$this->assertSame([], Server::get(BanMapper::class)->findActiveForKeys([self::IP], time()));
		$this->assertSame(ResponseOutcome::NOTE_HELD_BACK, $this->onlyDetection()->getActionList()[0]['note']);

		$this->resetTables();
		$this->assertNotNull($this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php', headers: $lure, method: 'POST'), 'No image or link makes a POST');
	}

	public function testAProbeLoggedInUsersMakeForAnotherSiteDoesNotBlockTheirAddress(): void {
		$this->settingsEditor()->setParam(InjectionProbe::ID, InjectionProbe::PARAM_AUTHENTICATED_MODE, 'protect');
		$lure = ['Sec-Fetch-Site' => 'cross-site', 'Sec-Fetch-Dest' => 'image'];
		$this->assertNull($this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php', cookies: [$this->sessionCookie() => 'x'], headers: $lure));
		$this->assertNull($this->responder->resolve($this->user('alice')));
		$this->assertSame([], Server::get(BanMapper::class)->findActiveForKeys([self::IP], time()));
		$this->assertSame('alice', $this->onlyDetection()->getUid());
	}

	public function testCustomAndDisabledSignaturesFromTheSettings(): void {
		$this->settingsEditor()->setParam(InjectionProbe::ID, InjectionProbe::PARAM_CUSTOM, ['dbms_pipe\.receive_message']);
		$this->assertNotNull($this->decide('/index.php/apps/foo?id=DBMS_PIPE.RECEIVE_MESSAGE(%27a%27,5)', '/index.php'));
		$this->assertSame([CustomSignatures::idFor('dbms_pipe\.receive_message')], array_values(array_filter(
			InjectionProbeFacts::fromArray($this->onlyDetection()->getExplanationData()['facts'])->signatures,
			static fn (string $id): bool => str_starts_with($id, 'custom_'),
		)));

		$this->resetTables();
		$this->settingsEditor()->setParam(InjectionProbe::ID, InjectionProbe::PARAM_DISABLED, ['sql_union_select']);
		$this->assertNull($this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php'));
		$this->assertSame([], $this->detections());
	}

	public function testASlowCustomSignatureCannotBeSaved(): void {
		$this->expectException(\OCA\IntrusionDetection\Definition\InvalidParamException::class);
		$this->settingsEditor()->setParam(InjectionProbe::ID, InjectionProbe::PARAM_CUSTOM, ['(a+)+$']);
	}

	public function testTheGuardFailsOpen(): void {
		$inspector = $this->createMock(PayloadInspector::class);
		$inspector->method('inspect')->willThrowException(new \RuntimeException('broken'));
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error');
		$guard = new PayloadGuard(Server::get(IConfig::class), $this->addresses(), $this->container($inspector), $logger, Server::get(GuardTimer::class));
		$this->assertNull($guard->check($this->request('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php')));
	}

	public function testCheckReadsParsedFormFieldsOfPostRequestsOnly(): void {
		$saved = $_POST;
		try {
			$_POST = ['user' => 'admin', 'x' => '1 UNION SELECT 1'];
			$guard = new PayloadGuard(Server::get(IConfig::class), $this->addresses(), $this->container(), Server::get(LoggerInterface::class), Server::get(GuardTimer::class));
			$this->assertNull($guard->check($this->request('/index.php/login', '/index.php')), 'GET ignores form fields');
			$this->assertNotNull($guard->check($this->request('/index.php/login', '/index.php', method: 'POST')));
			$this->assertSame('x', InjectionProbeFacts::fromArray($this->onlyDetection()->getExplanationData()['facts'])->param);
		} finally {
			$_POST = $saved;
		}
	}

	public function testTheNarrativeNamesParameterSignaturesAndExcerpt(): void {
		$this->decide('/index.php/apps/foo?data=JyBPUiAnMSc9JzE=', '/index.php');
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$facts = InjectionProbeFacts::fromArray($this->onlyDetection()->getExplanationData()['facts']);
		$this->assertSame('data', $facts->param);
		$this->assertSame(3, $facts->weights['sql_tautology'] ?? null);
		$this->assertSame(FormMatch::ENCODING_BASE64, $facts->encoding);
		$this->assertStringContainsString("' or '1'='1", $facts->excerpt);
		$this->assertFalse($facts->authenticated);
		$narrative = Server::get(NarrativeBuilder::class)->build($this->onlyDetection(), $l);
		$this->assertStringContainsString('Blocked ' . self::IP . '/32', implode("\n", $narrative->done));

		$this->resetTables();
		$this->decide('/index.php/apps/foo?id=1%20UNION%20SELECT%201', '/index.php', [], [$this->sessionCookie() => 'abc']);
		$this->responder->resolve($this->user('alice'));
		$this->assertTrue(InjectionProbeFacts::fromArray($this->onlyDetection()->getExplanationData()['facts'])->authenticated);
		$this->assertSame('alice', $this->onlyDetection()->getUid());
		$narrative = Server::get(NarrativeBuilder::class)->build($this->onlyDetection(), $l);
		$this->assertStringContainsString('logged-in user', (string)$narrative->observedBecause);
	}

	/**
	 * Values of password, token and excluded parameters never appear in a
	 * detection, a block, or the audit log.
	 */
	public function testNoSecretsAnywhere(): void {
		$secrets = ['S3cret-Pa55-Marker', 'T0ken-Marker-77', 'Excluded-Marker-42', 'C1ient-Secret-Marker'];
		$audit = [];
		$dispatcher = Server::get(IEventDispatcher::class);
		$listener = static function (CriticalActionPerformedEvent $event) use (&$audit): void {
			$audit[] = json_encode([$event->getLogMessage(), $event->getParameters()]);
		};
		$dispatcher->addListener(CriticalActionPerformedEvent::class, $listener);
		try {
			$attack = '%27%20UNION%20SELECT%20';
			$query = 'password=' . $secrets[0] . $attack . '&requesttoken=' . $secrets[1] . $attack . '&comment=' . $secrets[2] . $attack
				. '&client_secret=' . $secrets[3] . $attack . '&id=1' . $attack . '1';
			$this->assertNotNull($this->decide('/index.php/apps/foo?' . $query, '/index.php'));
			$this->decide('/index.php/login', '/index.php', [
				'user' => "admin' UNION SELECT 1",
				'password' => $secrets[0] . "' UNION SELECT 1",
				'requesttoken' => $secrets[1],
				'oc_token' => $secrets[1] . "' UNION SELECT 1",
				'message' => $secrets[2] . "' UNION SELECT 1",
			], [$this->sessionCookie() => 'abc']);
			$this->responder->resolve($this->user('alice'));
		} finally {
			$dispatcher->removeListener(CriticalActionPerformedEvent::class, $listener);
		}

		$stored = json_encode([$this->rows('ids_detections'), $this->rows('ids_bans'), $audit]);
		$this->assertNotFalse($stored);
		$this->assertStringContainsString('union select', $stored, 'The probe itself was recorded');
		foreach ($secrets as $secret) {
			$this->assertStringNotContainsStringIgnoringCase($secret, $stored);
		}
	}

	/**
	 * @param array<string, string> $post
	 * @param array<string, string> $cookies
	 * @param array<string, string> $headers
	 */
	private function decide(
		string $uri,
		string $script,
		array $post = [],
		array $cookies = [],
		array $headers = [],
		?IThrottler $throttler = null,
		?PayloadInspector $inspector = null,
		string $method = 'GET',
	): ?GuardDecision {
		$guard = new PayloadGuard(Server::get(IConfig::class), $this->addresses($throttler), $this->container($inspector), Server::get(LoggerInterface::class), Server::get(GuardTimer::class));
		return $guard->decide($this->request($uri, $script, $cookies, $headers, $method), RequestParts::fromUri($uri, $script, $post));
	}

	/**
	 * @param array<string, string> $cookies
	 * @param array<string, string> $headers
	 */
	private function request(string $uri, string $script, array $cookies = [], array $headers = [], string $method = 'GET'): IRequest {
		$server = [
			'REQUEST_URI' => $uri,
			'SCRIPT_NAME' => $script,
			'REMOTE_ADDR' => self::IP,
			'REQUEST_METHOD' => $method,
			'HTTP_USER_AGENT' => 'sqlmap/1.7',
		];
		foreach ($headers as $name => $value) {
			$server['HTTP_' . strtoupper(str_replace('-', '_', $name))] = $value;
		}
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturnCallback(static fn (string $key, string $default = ''): string => $default);
		$config->method('getSystemValue')->willReturnCallback(static fn (string $key, mixed $default = ''): mixed => $default);
		return new Request(['server' => $server, 'cookies' => $cookies, 'method' => $method], $this->createMock(IRequestId::class), $config);
	}

	/**
	 * The session cookie is named after the instance id.
	 */
	private function sessionCookie(): string {
		return Server::get(IConfig::class)->getSystemValueString('instanceid');
	}

	private function addresses(?IThrottler $throttler = null): RemoteAddressResolver {
		return new RemoteAddressResolver($this->createMock(IRequest::class), $throttler ?? $this->createMock(IThrottler::class), Server::get(ServerAddresses::class));
	}

	/**
	 * The app container as the guard sees it, with the test's request
	 * context, responder and session, and the instance id as session cookie.
	 */
	private function container(?PayloadInspector $inspector = null): ContainerInterface {
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(function (string $class) use ($inspector, $container): mixed {
			return match ($class) {
				PayloadResponder::class => $this->responder,
				DeferredHits::class => new DeferredHits($this->context, $container),
				PayloadInspector::class => $inspector ?? Server::get(PayloadInspector::class),
				IUserSession::class => $this->userSession(),
				default => Server::get($class),
			};
		});
		return $container;
	}

	private function userSession(): IUserSession {
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturnCallback(fn (): ?IUser => $this->sessionUser);
		return $session;
	}

	private function user(string $uid): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($uid);
		return $user;
	}

	/**
	 * @return list<Detection>
	 */
	private function detections(): array {
		return Server::get(DetectionMapper::class)->findList(new DetectionFilter(checkIds: [InjectionProbe::ID]));
	}

	private function onlyDetection(): Detection {
		$detections = $this->detections();
		$this->assertCount(1, $detections);
		return $detections[0];
	}

	/**
	 * @return list<array<string, mixed>>
	 */
	private function rows(string $table): array {
		return $this->db->getQueryBuilder()->select('*')->from($table)->executeQuery()->fetchAllAssociative();
	}

	private function resetTables(): void {
		foreach (['ids_detections', 'ids_bans'] as $table) {
			$this->db->getQueryBuilder()->delete($table)->executeStatement();
		}
		$this->context->set(PayloadResponder::CONTEXT_KEY, null);
	}
}
