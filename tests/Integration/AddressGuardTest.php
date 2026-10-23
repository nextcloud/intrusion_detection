<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Cache\KeyLock;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Guard\AddressGuard;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\State\AppState;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

#[Group('DB')]
class AddressGuardTest extends IntegrationTestCase {
	/** @var array<string, \OC\Memcache\ArrayCache> */
	private array $stores = [];

	/**
	 * The guard with each kind of cache the server may have.
	 *
	 * @return array<string, array{string}>
	 */
	public static function caches(): array {
		return ['distributed' => ['distributed'], 'local only' => ['local'], 'no memory cache' => ['none']];
	}

	#[DataProvider('caches')]
	public function testBannedAddressIsDeniedWithItsReference(string $cache): void {
		[$guard, $bans] = $this->guard($cache);
		$this->assertNull($guard->decisionFor('198.51.100.7'));

		$ban = $bans->ban(SourceKey::fromIp('198.51.100.7'), 'trap_url')->ban;
		$decision = $guard->decisionFor('198.51.100.7');
		$this->assertNotNull($decision);
		$this->assertSame($ban->getDisplayReference(), $decision->getReference());
		$this->assertEqualsWithDelta(14400, $decision->getRetryAfter(), 5);

		$this->assertNull($guard->decisionFor('198.51.100.8'), 'Another address is not blocked');
	}

	#[DataProvider('caches')]
	public function testLiftingTakesEffectAtOnce(string $cache): void {
		[$guard, $bans] = $this->guard($cache);
		$ban = $bans->ban(SourceKey::fromIp('198.51.100.7'), 'trap_url')->ban;
		$this->assertNotNull($guard->decisionFor('198.51.100.7'));
		$bans->lift($ban, 'admin', '');
		$this->assertNull($guard->decisionFor('198.51.100.7'));
	}

	public function testANetworkBanCoversEveryAddressInIt(): void {
		[$guard, $bans] = $this->guard('distributed');
		$bans->banManually('198.51.100.0/24', 1, 'admin', null);
		$this->assertNotNull($guard->decisionFor('198.51.100.200'));
		$this->assertNull($guard->decisionFor('198.51.101.1'));
	}

	public function testTheConfigSwitchTurnsTheGuardOff(): void {
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueBool')->with(AddressGuard::DISABLE_SWITCH)->willReturn(true);
		[$guard, $bans] = $this->guard('distributed', $config);
		$bans->ban(SourceKey::fromIp('198.51.100.7'), 'trap_url');
		$this->assertNull($guard->decisionFor('198.51.100.7'));
	}

	public function testTheMasterSwitchTurnsTheGuardOff(): void {
		[$guard, $bans] = $this->guard('distributed');
		$bans->ban(SourceKey::fromIp('198.51.100.7'), 'trap_url');
		$this->appConfig->setValueBool(Application::APP_ID, GlobalSettings::ENABLED, false);
		$this->assertNull($guard->decisionFor('198.51.100.7'));
	}

	public function testTheAllowlistWinsOverABlock(): void {
		[$guard, $bans] = $this->guard('distributed');
		$bans->banManually('198.51.100.7', 1, 'admin', null);
		$throttler = $this->createMock(IThrottler::class);
		$throttler->method('isBypassListed')->willReturn(true);
		[$allowGuard] = $this->guard('distributed', null, $throttler);
		$this->assertNotNull($guard->decisionFor('198.51.100.7'));
		$this->assertNull($allowGuard->decisionFor('198.51.100.7'));
	}

	public function testGarbageAddressesAreLetThrough(): void {
		[$guard] = $this->guard('distributed');
		$this->assertNull($guard->decisionFor(''));
		$this->assertNull($guard->decisionFor('not-an-ip'));
	}

	public function testTheVerdictIsSharedWithTheRestOfTheRequest(): void {
		$context = new RequestContext();
		[$guard] = $this->guard('distributed', context: $context);
		$guard->decisionFor('198.51.100.7');
		$this->assertNotNull($context->verdict());
		$this->assertFalse($context->verdict()->isDenied(time()));
	}

	public function testAVerdictResolvedInAWebRequestRemembersTheServersAddress(): void {
		[$guard] = $this->guard('distributed');
		$_SERVER['SERVER_ADDR'] = '192.0.2.10';
		try {
			$guard->decisionFor('198.51.100.7');
		} finally {
			unset($_SERVER['SERVER_ADDR']);
		}
		$this->assertTrue(Server::get(ServerAddresses::class)->contains(SourceKey::fromIp('192.0.2.10')), 'Known from now on, also to cron and occ');
	}

	/**
	 * @return array{0: AddressGuard, 1: BanService}
	 */
	private function guard(string $cache, ?IConfig $config = null, ?IThrottler $throttler = null, ?RequestContext $context = null): array {
		$factory = $this->cacheFactory($cache);
		$addressCache = new AddressCache($factory, Server::get(AppState::class));
		$time = Server::get(ITimeFactory::class);
		$throttler ??= $this->createMock(IThrottler::class);
		$request = $this->createMock(\OCP\IRequest::class);
		$addresses = new RemoteAddressResolver($request, $throttler, Server::get(ServerAddresses::class));

		$bans = new BanService(
			Server::get(\OCA\IntrusionDetection\Db\BanMapper::class),
			Server::get(\OCA\IntrusionDetection\Response\BanExemptions::class),
			$this->appSettings(),
			$addressCache,
			Server::get(AddressResolver::class),
			$addresses,
			Server::get(\OCA\IntrusionDetection\Net\ProtectedRanges::class),
			Server::get(\OCA\IntrusionDetection\Response\FlaggedSources::class),
			Server::get(KeyLock::class),
			$time,
			Server::get(\OCP\Security\ISecureRandom::class),
			Server::get(\OCA\IntrusionDetection\Event\TypedEvents::class),
			Server::get(AppState::class),
			Server::get(\OCA\IntrusionDetection\Audit\AuditLogger::class),
		);
		if ($config === null) {
			$config = $this->createMock(IConfig::class);
			$config->method('getSystemValueBool')->willReturn(false);
		}
		$guard = new AddressGuard(
			$config,
			$this->appSettings(),
			$addressCache,
			Server::get(AddressResolver::class),
			$addresses,
			$context ?? new RequestContext(),
			$time,
			new GuardTimer($factory, $time),
		);
		return [$guard, $bans];
	}

	private function cacheFactory(string $kind): Caches {
		// One in-memory store per test and cache kind, so the caches the guard
		// and the ban service create behave like one Redis or APCu.
		// A distributed cache is another class than the local one, as Redis is to APCu.
		$this->stores[$kind] ??= $kind === 'distributed'
			? new class('ids-test-' . $kind) extends \OC\Memcache\ArrayCache {
			}
		: new \OC\Memcache\ArrayCache('ids-test-' . $kind);
		$store = $this->stores[$kind];
		return match ($kind) {
			'distributed' => new FixedCaches($store, null, true),
			'local' => new FixedCaches($store),
			default => FixedCaches::none(),
		};
	}
}
