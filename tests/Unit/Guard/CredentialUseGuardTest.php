<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Guard;

use OC\AppFramework\Http\Request;
use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialTracker;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialUse;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialUseResolver;
use OCA\IntrusionDetection\Check\CredentialUse\PresentedCredential;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Guard\AddressGuard;
use OCA\IntrusionDetection\Guard\CredentialUseGuard;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCA\IntrusionDetection\Tests\BasicAuthServer;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ICacheFactory;
use OCP\IConfig;
use OCP\IRequest;
use OCP\IRequestId;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * The guard's per-request cost and its preconditions, with a spy cache.
 */
class CredentialUseGuardTest extends TestCase {
	use BasicAuthServer;

	private const COOKIE = 'oc1234567890';

	private SpyCache $cache;
	private ICacheFactory&MockObject $cacheFactory;
	private Settings&MockObject $settings;
	private ContainerInterface&MockObject $container;
	private RemoteAddressResolver&MockObject $addresses;
	private LoggerInterface&MockObject $logger;
	private RequestContext $context;
	private bool $distributed = false;
	private bool $local = true;
	private bool $disabled = false;
	private string $mode = 'protect';
	private bool $ignored = false;
	private int $now = 1792411200;
	/** @var list<\Closure> */
	private array $shutdown = [];

	protected function setUp(): void {
		parent::setUp();
		$this->cache = new SpyCache();
		$this->cacheFactory = $this->createMock(ICacheFactory::class);
		$this->cacheFactory->method('isAvailable')->willReturnCallback(fn (): bool => $this->distributed);
		$this->cacheFactory->method('isLocalCacheAvailable')->willReturnCallback(fn (): bool => $this->local);
		$this->cacheFactory->method('createLocal')->willReturn($this->cache);
		$this->cacheFactory->method('createDistributed')->willReturn($this->cache);
		$this->settings = $this->createMock(Settings::class);
		$this->settings->method('configuredMode')->with(TokenConcurrentUse::ID)->willReturnCallback(fn (): Mode => Mode::from($this->mode));
		$this->settings->method('isEnabled')->willReturn(true);
		$this->settings->method('paramInt')->willReturnCallback(static fn (string $id, string $name): int => $name === TokenConcurrentUse::PARAM_WINDOW ? 900 : 3);
		$this->addresses = $this->createMock(RemoteAddressResolver::class);
		$this->addresses->method('isIgnored')->willReturnCallback(fn (): bool => $this->ignored);
		$this->container = $this->createMock(ContainerInterface::class);
		$this->container->method('get')->with(RemoteAddressResolver::class)->willReturn($this->addresses);
		$this->logger = $this->createMock(LoggerInterface::class);
		$this->context = new RequestContext();
	}

	public function testTheCommonCaseIsOneCacheGetAndNoWrite(): void {
		$this->knownFrom('198.51.100.7');
		$guard = $this->guard();
		$this->container->expects($this->never())->method('get');
		$this->settings->expects($this->never())->method('paramInt');
		for ($i = 0; $i < 10; $i++) {
			$this->now += 20;
			$before = $this->cache->gets;
			$this->assertNull($guard->check($this->basic('198.51.100.' . (7 + $i))));
			$this->assertSame($before + 1, $this->cache->gets, 'Exactly one get per request');
		}
		$this->assertSame(0, $this->cache->sets, 'No write while the network stays the same');
		$this->assertSame([], $this->shutdown);
	}

	public function testTheNetworkIsRefreshedEveryFiveMinutesAndOnAChange(): void {
		$this->knownFrom('198.51.100.7');
		$guard = $this->guard();
		$this->now += 299;
		$guard->check($this->basic('198.51.100.7'));
		$this->assertSame(0, $this->cache->sets);
		$this->now += 1;
		$guard->check($this->basic('198.51.100.7'));
		$this->assertSame(1, $this->cache->sets, 'Refreshed after five minutes');
		$this->now += 1;
		$guard->check($this->basic('203.0.113.9'));
		$this->assertSame(2, $this->cache->sets, 'Written when the network changes');
	}

	public function testACredentialSeenForTheFirstTimeIsOnlyWrittenAfterItLoggedIn(): void {
		for ($i = 0; $i < 20; $i++) {
			$this->context = new RequestContext();
			$this->now += 1;
			$this->assertNull($this->guard()->check($this->request('203.0.113.' . $i, ['PHP_AUTH_USER' => 'alice', 'PHP_AUTH_PW' => 'guess-' . $i])));
			$use = $this->context->get(CredentialUseResolver::CONTEXT_KEY);
			$this->assertInstanceOf(CredentialUse::class, $use);
			$this->assertTrue($use->unknown);
			$this->assertTrue($use->needsResolution(), 'Recorded after authentication, if it logs in');
		}
		$this->assertSame([20, 0], [$this->cache->gets, $this->cache->sets], 'Made-up credentials leave nothing in the cache');
		$this->assertCount(20, $this->shutdown, 'One end-of-request callback per request');

		$guard = $this->guard();
		$guard->check($this->request('203.0.113.1', ['PHP_AUTH_USER' => 'alice', 'PHP_AUTH_PW' => 'one']));
		$guard->check($this->request('203.0.113.2', ['PHP_AUTH_USER' => 'alice', 'PHP_AUTH_PW' => 'two']));
		$this->assertCount(21, $this->shutdown, 'Registered once per process');
	}

	public function testTheAddressGuardsVerdictSparesReadingTheMasterSwitch(): void {
		$this->context->setVerdict(new Verdict());
		$this->settings->expects($this->never())->method('isEnabled');
		$this->guard()->check($this->basic('198.51.100.7'));
		$this->assertSame(1, $this->cache->gets);
	}

	public function testRequestsWithoutCredentialsCostNoCacheOrSetting(): void {
		$this->cacheFactory->expects($this->never())->method('isLocalCacheAvailable');
		$this->settings->expects($this->never())->method('isEnabled');
		$this->settings->expects($this->never())->method('configuredMode');
		$guard = $this->guard();
		$this->assertNull($guard->check($this->request('198.51.100.7', [], ['nc_token' => 'remember-me'])));
		$this->assertNull($guard->check($this->request('198.51.100.7', ['HTTP_AUTHORIZATION' => 'Negotiate abc'])));
		$this->assertSame(0, $this->cache->gets);
		$this->assertNull($this->context->get(CredentialUseResolver::CONTEXT_KEY));
	}

	public function testWithoutAMemoryCacheNothingIsReadAtAll(): void {
		$this->local = false;
		$this->cacheFactory->expects($this->never())->method('createLocal');
		$this->cacheFactory->expects($this->never())->method('createDistributed');
		$this->settings->expects($this->never())->method($this->anything());
		$this->container->expects($this->never())->method('get');
		$guard = $this->guard();
		foreach (['198.51.100.7', '203.0.113.9', '198.51.100.7', '203.0.113.9', '198.51.100.7'] as $ip) {
			$this->now += 10;
			$this->assertNull($guard->check($this->basic($ip)));
		}
		$this->assertSame(0, $this->cache->gets);
		$this->assertNull($this->context->get(CredentialUseResolver::CONTEXT_KEY));
	}

	public function testADistributedCacheIsPreferred(): void {
		$this->distributed = true;
		$this->cacheFactory->expects($this->once())->method('createDistributed');
		$this->cacheFactory->expects($this->never())->method('createLocal');
		$this->guard()->check($this->basic('198.51.100.7'));
		$this->assertSame(1, $this->cache->gets);
	}

	public function testOffAndTheEmergencySwitchSkipEverything(): void {
		$this->mode = 'off';
		$this->guard()->check($this->basic('198.51.100.7'));
		$this->assertSame(0, $this->cache->gets, 'Off: no cache access');

		$this->mode = 'observe';
		$this->disabled = true;
		$this->guard()->check($this->basic('198.51.100.7'));
		$this->assertSame(0, $this->cache->gets, 'disable_guards in config.php');

		$this->disabled = false;
		$this->guard()->check($this->basic('198.51.100.7'));
		$this->assertSame(1, $this->cache->gets, 'Observe tracks like Protect');
	}

	public function testABackAndForthIsKeptUntilAuthenticationDecides(): void {
		$this->knownFrom('198.51.100.7');
		foreach (['203.0.113.9', '198.51.100.7'] as $ip) {
			$this->now += 10;
			$this->context = new RequestContext();
			$guard = $this->guard();
			$guard->check($this->basic($ip));
			$use = $this->context->get(CredentialUseResolver::CONTEXT_KEY);
			$this->assertInstanceOf(CredentialUse::class, $use);
			$this->assertNull($use->switch);
		}
		$this->assertSame([], $this->shutdown);

		$this->now += 10;
		$this->context = new RequestContext();
		$guard = $this->guard();
		$this->assertNull($guard->check($this->basic('203.0.113.9')), 'Never refuses');
		$use = $this->context->get(CredentialUseResolver::CONTEXT_KEY);
		$this->assertInstanceOf(CredentialUse::class, $use);
		$this->assertSame(PresentedCredential::SCHEME_BASIC, $use->scheme);
		$this->assertSame(3, $use->switch?->switches);
		$this->assertCount(1, $this->shutdown, 'Resolved at the end of the request at the latest');
	}

	public function testTheAllowlistIsNotTracked(): void {
		$this->knownFrom('198.51.100.7');
		$this->ignored = true;
		$this->guard()->check($this->basic('203.0.113.9'));
		$this->assertSame([1, 0], [$this->cache->gets, $this->cache->sets]);
	}

	public function testAFailureLetsTheRequestThrough(): void {
		$this->cache->fail = true;
		$this->logger->expects($this->once())->method('error');
		$this->assertNull($this->guard()->check($this->basic('198.51.100.7')));
	}

	/**
	 * The credential logged in from this address before: it has an entry.
	 */
	private function knownFrom(string $ip): void {
		$credential = PresentedCredential::fromRequest($this->basic($ip), self::COOKIE);
		$this->assertNotNull($credential);
		$this->tracker()->track($this->fingerprinter()->credential($credential->keyMaterial()), SourceKey::fromIp($ip), $credential->userTag(), $this->now);
		$this->cache->reset();
	}

	private function tracker(): CredentialTracker {
		return new CredentialTracker($this->cacheFactory, $this->settings);
	}

	private function fingerprinter(): Fingerprinter {
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturn('instance-secret');
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		return new Fingerprinter($config, $time);
	}

	private function guard(): CredentialUseGuard {
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueBool')->with(AddressGuard::DISABLE_SWITCH)->willReturnCallback(fn (): bool => $this->disabled);
		$config->method('getSystemValueString')->willReturnCallback(static fn (string $key): string => match ($key) {
			'instanceid' => self::COOKIE,
			'secret' => 'instance-secret',
			default => '',
		});
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		$shutdown = &$this->shutdown;
		return new class($config, $this->settings, $this->fingerprinter(), $this->tracker(), $this->context, $time, $this->container, $this->logger, $this->createMock(GuardTimer::class), $shutdown) extends CredentialUseGuard {
			/** @var list<\Closure> */
			private array $registered;

			/** @param list<\Closure> $registered */
			public function __construct(IConfig $config, Settings $settings, Fingerprinter $fingerprinter, CredentialTracker $tracker, RequestContext $context, ITimeFactory $time, ContainerInterface $container, LoggerInterface $logger, GuardTimer $timer, array &$registered) {
				parent::__construct($config, $settings, $fingerprinter, $tracker, $context, $time, $container, $logger, $timer);
				$this->registered = &$registered;
			}

			protected function registerShutdown(\Closure $callback): void {
				$this->registered[] = $callback;
			}
		};
	}

	private function basic(string $ip): IRequest {
		return $this->request($ip, ['PHP_AUTH_USER' => 'alice', 'PHP_AUTH_PW' => 'AbCdE-FgHiJ-KlMnO-PqRsT-UvWxY']);
	}

	private function request(string $ip, array $server, array $cookies = []): IRequest {
		$this->setBasicCredentials($server['PHP_AUTH_USER'] ?? null, $server['PHP_AUTH_PW'] ?? null);
		unset($server['PHP_AUTH_USER'], $server['PHP_AUTH_PW']);
		return new Request(['server' => $server + ['REMOTE_ADDR' => $ip], 'cookies' => $cookies], $this->createMock(IRequestId::class), $this->createMock(IConfig::class));
	}
}

/**
 * A local cache that counts what the guard asks of it.
 */
class SpyCache extends ArrayCache {
	public int $gets = 0;
	public int $sets = 0;
	public bool $fail = false;

	public function reset(): void {
		$this->gets = 0;
		$this->sets = 0;
	}

	#[\Override]
	public function get($key) {
		if ($this->fail) {
			throw new \RuntimeException('The cache is down');
		}
		$this->gets++;
		return parent::get($key);
	}

	#[\Override]
	public function set($key, $value, $ttl = 0) {
		$this->sets++;
		return parent::set($key, $value, $ttl);
	}
}
