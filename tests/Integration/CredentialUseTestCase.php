<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\AppFramework\Http\Request;
use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUseDetector;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialTracker;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialUseResolver;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Guard\CredentialUseGuard;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\KnownDevice\IKnownDevices;
use OCA\IntrusionDetection\Listener\CredentialUseLoginListener;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCA\IntrusionDetection\Response\Tokens;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\Rules\CredentialUseRule;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Token\IProvider;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IAppConfig;
use OCP\ICache;
use OCP\ICacheFactory;
use OCP\IConfig;
use OCP\IRequestId;
use OCP\ISession;
use OCP\IUser;
use OCP\IUserSession;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use OCP\User\Events\UserLoggedInEvent;
use Psr\Container\ContainerInterface;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;

/**
 * Runs requests through the credential check as core would: the guard
 * before authentication, then what authentication leaves in the session
 * (and the login event, where core dispatches one), then the session-state
 * rule, then the end of the request. All requests share one memory cache,
 * an {@see ArrayCache} standing in for APCu or Redis.
 */
abstract class CredentialUseTestCase extends AccountTestCase {
	protected const HOME = '198.51.100.7';
	protected const AWAY = '203.0.113.50';

	protected ArrayCache $cache;
	protected CredentialTracker $tracker;
	protected int $now;
	/** @var list<array{string, int}> calls of the known-device hook */
	protected array $forgotten = [];
	/** @var list<string> what the app logged */
	protected array $logged = [];
	protected string $cookieName;

	protected function setUp(): void {
		parent::setUp();
		$this->cache = new ArrayCache();
		$this->settings = new Settings(
			Server::get(IAppConfig::class),
			Server::get(CheckRegistry::class),
			Server::get(ITimeFactory::class),
			new Prerequisites($this->cacheFactory($this->cache), Server::get(IConfig::class)),
			Server::get(GlobalSettings::class),
			Server::get(IEventDispatcher::class),
		);
		$this->tracker = new CredentialTracker($this->cacheFactory($this->cache), $this->settings);
		$this->now = time();
		$this->cookieName = Server::get(IConfig::class)->getSystemValueString('instanceid');
	}

	/**
	 * A factory that offers this cache as the local cache, or no memory cache at all.
	 */
	protected function cacheFactory(?ICache $cache): ICacheFactory {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn(false);
		$factory->method('isLocalCacheAvailable')->willReturn($cache !== null);
		if ($cache !== null) {
			$factory->method('createLocal')->willReturn($cache);
		}
		return $factory;
	}

	/**
	 * One request, ten seconds after the previous one.
	 *
	 * @param array<string, string> $server
	 * @param array<string, string> $cookies
	 * @param ?\Closure(TestSession, CredentialUseLoginListener): ?IUser $authenticate what core's
	 *                                                                                 authentication does; returns the logged-in user
	 * @param bool $rule whether the request reaches a controller or WebDAV, where the session-state rules run
	 */
	protected function send(string $ip, array $server, array $cookies, ?\Closure $authenticate, bool $rule = true): RequestContext {
		$this->now += 10;
		$this->sessionUser = null;
		$request = new Request([
			'server' => $server + ['REMOTE_ADDR' => $ip, 'REQUEST_METHOD' => 'PROPFIND', 'HTTP_USER_AGENT' => 'Mozilla/5.0 (Linux) mirall/3.15.0'],
			'cookies' => $cookies,
		], $this->createMock(IRequestId::class), Server::get(IConfig::class));
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		$context = new RequestContext();
		$session = new TestSession();
		$container = new TestContainer();
		$logger = $this->logger();

		$guard = new TestCredentialUseGuard(Server::get(IConfig::class), $this->settings, new Fingerprinter(Server::get(IConfig::class), $time), $this->tracker, $context, $time, $container, $logger, Server::get(GuardTimer::class));
		$knownDevices = new class($this->forgotten) implements IKnownDevices {
			/** @param list<array{string, int}> $calls */
			public function __construct(
				private array &$calls,
			) {
			}

			public function forgetCurrentDevice(string $uid, int $detectionId): void {
				$this->calls[] = [$uid, $detectionId];
			}
		};
		$container->services = [
			IUserSession::class => $this->userSession,
			ISession::class => $session,
			CurrentSession::class => new CurrentSession($session, Server::get(IProvider::class), $logger),
			CredentialTracker::class => $this->tracker,
			ITimeFactory::class => $time,
			RemoteAddressResolver::class => new RemoteAddressResolver($request, Server::get(IThrottler::class), Server::get(ServerAddresses::class)),
			TokenConcurrentUseDetector::class => new TokenConcurrentUseDetector($this->settings, $this->engine(), Server::get(Tokens::class), $knownDevices),
			CredentialUseResolver::class => new CredentialUseResolver($context, $request, Server::get(IConfig::class), $container, $logger),
		];

		$this->assertNull($guard->check($request), 'The guard never refuses');
		if ($authenticate !== null) {
			$this->sessionUser = $authenticate($session, new CredentialUseLoginListener($context, $container, $logger));
		}
		if ($rule && $this->sessionUser !== null) {
			$rule = new CredentialUseRule($context, $container);
			$this->assertNull($rule->check(new SessionState($session, $logger), RequestTarget::dav('PROPFIND', '/remote.php/dav/files/x/')), 'The rule never blocks');
		}
		foreach ($guard->shutdown as $callback) {
			$callback();
		}
		return $context;
	}

	/**
	 * Basic credentials as a WebDAV client sends them.
	 *
	 * @return array<string, string>
	 */
	protected function basic(string $user, string $password): array {
		return ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($user . ':' . $password), 'PHP_AUTH_USER' => $user, 'PHP_AUTH_PW' => $password];
	}

	/**
	 * Core's login with an app password: the login event, then the
	 * session's token id and app password.
	 *
	 * @param array{id: int, secret: string} $token
	 */
	protected function appPasswordLogin(IUser $user, array $token): \Closure {
		return function (TestSession $session, CredentialUseLoginListener $listener) use ($user, $token): IUser {
			$session->set('token-id', $token['id']);
			$this->sessionUser = $user;
			$listener->handle(new UserLoggedInEvent($user, $user->getUID(), 'A-long-test-password-' . $user->getUID(), true));
			$session->set('app_password', $token['secret']);
			return $user;
		};
	}

	/**
	 * A browser session that is already logged in: no login event.
	 *
	 * @param array{id: int, secret: string} $token the session token
	 */
	protected function loggedInSession(IUser $user, array $token): \Closure {
		return function (TestSession $session) use ($user, $token): IUser {
			$session->id = $token['secret'];
			return $user;
		};
	}

	/**
	 * A login with the account's password over Basic.
	 */
	protected function passwordLogin(IUser $user): \Closure {
		return function (TestSession $session, CredentialUseLoginListener $listener) use ($user): IUser {
			$this->sessionUser = $user;
			$listener->handle(new UserLoggedInEvent($user, $user->getUID(), 'A-long-test-password-' . $user->getUID(), false));
			return $user;
		};
	}

	protected function logger(): LoggerInterface {
		return new class($this->logged) extends AbstractLogger {
			/** @param list<string> $lines */
			public function __construct(
				private array &$lines,
			) {
			}

			public function log($level, string|\Stringable $message, array $context = []): void {
				$this->lines[] = $message . ' ' . json_encode($context, JSON_PARTIAL_OUTPUT_ON_ERROR);
			}
		};
	}
}

/**
 * The guard, with the end of the request under the test's control.
 */
class TestCredentialUseGuard extends CredentialUseGuard {
	/** @var list<\Closure> */
	public array $shutdown = [];

	#[\Override]
	protected function registerShutdown(\Closure $callback): void {
		$this->shutdown[] = $callback;
	}
}

/**
 * The server container with the request's own services.
 */
class TestContainer implements ContainerInterface {
	/** @var array<string, object> */
	public array $services = [];

	public function get(string $id): mixed {
		return $this->services[$id] ?? Server::get($id);
	}

	public function has(string $id): bool {
		return isset($this->services[$id]) || Server::get(ContainerInterface::class)->has($id);
	}
}
