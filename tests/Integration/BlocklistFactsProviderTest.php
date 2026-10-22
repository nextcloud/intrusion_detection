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
use OCA\IntrusionDetection\Blocklist\BlocklistFactsProvider;
use OCA\IntrusionDetection\Blocklist\ListState;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Blocklist\StateStore;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch;
use OCA\IntrusionDetection\Check\Checks\RiskyNetwork;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\BlocklistRangeMapper;
use OCA\IntrusionDetection\Db\BlocklistStatMapper;
use OCA\IntrusionDetection\Db\StateMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Guard\AddressGuard;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ICacheFactory;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\IRequest;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

#[Group('DB')]
class BlocklistFactsProviderTest extends IntegrationTestCase {
	private const NOW = 1792490400;

	private Settings $settings;
	/** @var list<string> lists the provider looked up */
	private array $queried = [];

	protected function setUp(): void {
		parent::setUp();
		$this->settings = Server::get(Settings::class);
		$this->settings->setMode(BlocklistMatch::ID, Mode::Protect);
		$this->settings->setGlobal(GlobalSettings::BLOCKLIST_SOURCES, json_encode([
			['id' => 'drop', 'url' => 'https://lists.example.org/drop.txt', 'purpose' => 'deny', 'mode' => 'protect', 'enabled' => true],
			['id' => 'watch', 'url' => 'https://lists.example.org/watch.txt', 'purpose' => 'deny', 'mode' => 'observe', 'enabled' => true],
			['id' => 'cloud', 'url' => 'https://lists.example.org/cloud.txt', 'purpose' => 'hosting', 'enabled' => true],
			['id' => 'exits', 'url' => 'https://lists.example.org/exits.txt', 'purpose' => 'tor', 'enabled' => true],
			['id' => 'unused', 'url' => 'https://lists.example.org/unused.txt', 'purpose' => 'deny', 'mode' => 'protect', 'enabled' => false],
		]));
		$this->load('drop', ['198.51.100.0/24', '2001:db8:1::/48']);
		$this->load('watch', ['203.0.113.0/25']);
		$this->load('cloud', ['192.0.2.0/24', '203.0.113.0/24']);
		$this->load('exits', ['192.0.2.77']);
		$this->load('unused', ['192.0.2.0/24']);
	}

	public function testAProtectListRefusesWithItsReference(): void {
		$facts = $this->provider()->facts(SourceKey::fromIp('198.51.100.7'));
		$this->assertSame(self::NOW + AddressCache::OK_TTL, $facts->denyUntil);
		$this->assertSame(Server::get(SourceRepository::class)->reference('drop'), $facts->reference);
		$this->assertSame([], $facts->attributes);
	}

	public function testAnObserveListOnlyAddsAnAttribute(): void {
		$facts = $this->provider()->facts(SourceKey::fromIp('203.0.113.9'));
		$this->assertSame(0, $facts->denyUntil);
		$this->assertSame(['list:watch', 'hosting', 'net:cloud'], $facts->attributes);
	}

	public function testWhileTheCheckObservesAProtectListOnlyAddsAnAttribute(): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);
		$facts = $this->provider()->facts(SourceKey::fromIp('198.51.100.7'));
		$this->assertSame(0, $facts->denyUntil);
		$this->assertSame(['list:drop'], $facts->attributes);
	}

	public function testAttributeListsAreSkippedWhileNothingUsesThem(): void {
		$this->settings->setMode(RiskyNetwork::ID, Mode::Off);
		$this->settings->setGlobal(GlobalSettings::RISK_ENABLED, false);
		$this->assertSame([], $this->provider()->facts(SourceKey::fromIp('192.0.2.77'))->attributes);
		$this->assertNotContains('cloud', $this->queried);
		$this->assertNotContains('exits', $this->queried);

		$this->settings->setGlobal(GlobalSettings::RISK_ENABLED, true);
		$this->assertSame(['hosting', 'net:cloud', 'tor', 'net:exits'], $this->provider()->facts(SourceKey::fromIp('192.0.2.77'))->attributes, 'The risk score uses them');
		$this->settings->setGlobal(GlobalSettings::RISK_ENABLED, false);
		$this->settings->setMode(RiskyNetwork::ID, Mode::Observe);
		$this->assertSame(['hosting', 'net:cloud', 'tor', 'net:exits'], $this->provider()->facts(SourceKey::fromIp('192.0.2.77'))->attributes, 'The check uses them');
	}

	public function testAttributeListsMatchEveryAddressOfAnIpv6Network(): void {
		$this->load('cloud', ['2001:db8:aa:1::/64']);
		$this->assertSame(['hosting', 'net:cloud'], $this->provider()->facts(SourceKey::fromIp('2001:db8:aa:1::'))->attributes);
		$this->assertSame(['hosting', 'net:cloud'], $this->provider()->facts(SourceKey::fromIp('2001:db8:aa:1:ffff:ffff:ffff:ffff'))->attributes);
		$this->assertSame([], $this->provider()->facts(SourceKey::fromIp('2001:db8:aa:2::1'))->attributes);
		$this->assertSame([], $this->provider()->facts(SourceKey::fromIp('2001:db8:aa:0:ffff:ffff:ffff:ffff'))->attributes);
	}

	public function testFactsOfAWholeSlash64HoldForEveryAddressInIt(): void {
		$this->load('cloud', ['2001:db8:aa:1::/64']);
		$this->assertFalse($this->provider()->facts(SourceKey::fromIp('2001:db8:aa:1::5'))->perAddress, 'Listed as a whole');
		$this->assertFalse($this->provider()->facts(SourceKey::fromIp('2001:db8:aa:2::5'))->perAddress, 'Not listed at all');
		$denied = $this->provider()->facts(SourceKey::fromIp('2001:db8:1:7::1'));
		$this->assertGreaterThan(0, $denied->denyUntil, 'Inside the /48 of the protect list');
		$this->assertFalse($denied->perAddress);
	}

	public function testAnEntrySmallerThanTheSlash64IsLookedUpPerAddress(): void {
		$this->load('exits', ['2001:db8:bb:1::77', '2001:db8:bb:2::/72']);
		$exit = $this->provider()->facts(SourceKey::fromIp('2001:db8:bb:1::77'));
		$this->assertSame(['tor', 'net:exits'], $exit->attributes);
		$this->assertTrue($exit->perAddress);
		$neighbour = $this->provider()->facts(SourceKey::fromIp('2001:db8:bb:1::78'));
		$this->assertSame([], $neighbour->attributes);
		$this->assertTrue($neighbour->perAddress, 'The /64 holds an entry, so its verdicts are per address');
		$this->assertTrue($this->provider()->facts(SourceKey::fromIp('2001:db8:bb:2:ffff::1'))->perAddress, 'Behind a range that ends inside the /64');
		$this->assertFalse($this->provider()->facts(SourceKey::fromIp('2001:db8:bb:3::1'))->perAddress);
	}

	public function testAttributeListsGiveHostingAndTor(): void {
		$this->assertSame(['hosting', 'net:cloud', 'tor', 'net:exits'], $this->provider()->facts(SourceKey::fromIp('192.0.2.77'))->attributes);
		$this->assertSame(['hosting', 'net:cloud'], $this->provider()->facts(SourceKey::fromIp('192.0.2.78'))->attributes);
	}

	/**
	 * @return array<string, array{string, bool}>
	 */
	public static function edges(): array {
		return [
			'first address' => ['198.51.100.0', true],
			'last address' => ['198.51.100.255', true],
			'just below' => ['198.51.99.255', false],
			'just above' => ['198.51.101.0', false],
			'IPv6 first' => ['2001:db8:1::', true],
			'IPv6 last' => ['2001:db8:1:ffff:ffff:ffff:ffff:ffff', true],
			'IPv6 just above' => ['2001:db8:2::', false],
			'IPv6 just below' => ['2001:db8:0:ffff:ffff:ffff:ffff:ffff', false],
			'IPv4-mapped IPv6' => ['::ffff:198.51.100.9', true],
			'unrelated' => ['8.8.8.8', false],
		];
	}

	#[DataProvider('edges')]
	public function testRangeEdges(string $ip, bool $listed): void {
		$this->assertSame($listed, $this->provider()->facts(SourceKey::fromIp($ip))->denyUntil > 0);
	}

	public function testANearerRangeOfAnotherListDoesNotHideAMatch(): void {
		// 203.0.113.0/24 (cloud) starts at the same address as 203.0.113.0/25 (watch);
		// each list is looked up on its own.
		$this->assertSame(['hosting', 'net:cloud'], $this->provider()->facts(SourceKey::fromIp('203.0.113.200'))->attributes);
	}

	public function testBlocklistsAreNotLookedUpWhileTheCheckIsOff(): void {
		$this->settings->setMode(BlocklistMatch::ID, Mode::Off);
		$facts = $this->provider()->facts(SourceKey::fromIp('198.51.100.7'));
		$this->assertSame(0, $facts->denyUntil);
		$this->assertSame(['cloud', 'exits'], $this->queried, 'Only the attribute lists');
	}

	public function testDisabledAndUnsyncedListsAreNotLookedUp(): void {
		Server::get(StateStore::class)->remove('exits');
		$this->provider()->facts(SourceKey::fromIp('192.0.2.1'));
		$this->assertSame(['drop', 'watch', 'cloud'], $this->queried);
	}

	public function testMatchesAreCountedPerListAndDayWithAMemoryCache(): void {
		$provider = $this->provider(withCache: true);
		$provider->facts(SourceKey::fromIp('198.51.100.7'));
		$provider->facts(SourceKey::fromIp('198.51.100.8'));
		$provider->facts(SourceKey::fromIp('198.51.100.7'));
		$provider->facts(SourceKey::fromIp('192.0.2.5'));
		$row = Server::get(BlocklistStatMapper::class)->find('drop', '2026-10-20');
		$this->assertNotNull($row);
		$this->assertSame(3, $row['matches']);
		$this->assertSame(['198.51.100.8', '198.51.100.7'], $row['sample'], 'Each address once, the latest last');
		$this->assertSame(1, Server::get(BlocklistStatMapper::class)->find('cloud', '2026-10-20')['matches'] ?? null, 'Network lists are counted too');
	}

	public function testTheSampleKeepsTheLastTwentyAddresses(): void {
		$provider = $this->provider(withCache: true);
		for ($i = 1; $i <= 25; $i++) {
			$provider->facts(SourceKey::fromIp('198.51.100.' . $i));
		}
		$row = Server::get(BlocklistStatMapper::class)->find('drop', '2026-10-20');
		$this->assertSame(25, $row['matches'] ?? null);
		$this->assertCount(BlocklistStatMapper::SAMPLE_SIZE, $row['sample'] ?? []);
		$this->assertSame('198.51.100.25', ($row['sample'] ?? [])[19]);
	}

	public function testNothingIsCountedWithoutAMemoryCache(): void {
		$this->provider()->facts(SourceKey::fromIp('198.51.100.7'));
		$this->assertNull(Server::get(BlocklistStatMapper::class)->find('drop', '2026-10-20'));
	}

	public function testTheAddressGuardRefusesAProtectListAddress(): void {
		[$guard, $context] = $this->guard();
		$decision = $guard->decisionFor('198.51.100.7');
		$this->assertNotNull($decision);
		$this->assertSame(Server::get(SourceRepository::class)->reference('drop'), $decision->getReference());
		$this->assertSame(AddressCache::OK_TTL, $decision->getRetryAfter());

		$this->assertNull($guard->decisionFor('203.0.113.9'), 'An Observe list does not refuse');
		$this->assertSame(['list:watch', 'hosting', 'net:cloud'], $context->verdict()?->attributes);
		$this->assertNull($guard->decisionFor('8.8.8.8'));
	}

	public function testTheAllowlistWinsOverABlocklist(): void {
		[$guard] = $this->guard(allowlisted: true);
		$this->assertNull($guard->decisionFor('198.51.100.7'));
	}

	public function testAListBlockIsResolvedAgainWhenItEnds(): void {
		[, , $resolver] = $this->guard();
		$verdict = $resolver->resolve(SourceKey::fromIp('198.51.100.7'));
		$this->assertSame(self::NOW + AddressCache::OK_TTL, $verdict->denyUntil);
		$this->assertSame($verdict->denyUntil, $verdict->cacheUntil);
	}

	public function testALongerBanWinsOverAListMatch(): void {
		$ban = new Ban();
		$ban->setReference('K7Q2MPXA');
		$ban->setCidr('198.51.100.7/32');
		$ban->setScope(Ban::SCOPE_IP);
		$ban->setBanKey('198.51.100.7');
		$ban->setLevel(1);
		$ban->setCheckId('trap_url');
		$ban->setCreatedAt(self::NOW);
		$ban->setExpiresAt(self::NOW + 14400);
		Server::get(BanMapper::class)->insert($ban);
		[, , $resolver] = $this->guard();
		$verdict = $resolver->resolve(SourceKey::fromIp('198.51.100.7'));
		$this->assertSame(self::NOW + 14400, $verdict->denyUntil);
		$this->assertSame('K7Q2-MPXA', $verdict->reference);
	}

	/**
	 * @param list<string> $cidrs
	 */
	private function load(string $id, array $cidrs): void {
		$ranges = RangeCodec::merge(array_map(static fn (string $c): string => RangeCodec::parseCompact($c), $cidrs));
		Server::get(BlocklistRangeMapper::class)->writeVersion($id, 3, $ranges);
		$state = new ListState(version: 3, ranges: count($ranges));
		Server::get(StateStore::class)->save($id, $state);
	}

	private function provider(bool $withCache = false): BlocklistFactsProvider {
		$test = $this;
		$ranges = new class(Server::get(IDBConnection::class), $test) extends BlocklistRangeMapper {
			public function __construct(
				IDBConnection $db,
				private readonly BlocklistFactsProviderTest $test,
			) {
				parent::__construct($db);
			}

			#[\Override]
			public function findContaining(string $listId, int $version, int $family, string $addressHex): ?array {
				$this->test->queried($listId);
				return parent::findContaining($listId, $version, $family, $addressHex);
			}
		};
		return new BlocklistFactsProvider(
			Server::get(SourceRepository::class),
			Server::get(StateStore::class),
			$ranges,
			Server::get(BlocklistStatMapper::class),
			$this->settings,
			$this->addressCache($withCache),
			$this->time(),
			Server::get(LoggerInterface::class),
		);
	}

	public function queried(string $listId): void {
		$this->queried[] = $listId;
	}

	/**
	 * @return array{0: AddressGuard, 1: RequestContext, 2: AddressResolver}
	 */
	private function guard(bool $allowlisted = false): array {
		$provider = $this->provider();
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->with(BlocklistFactsProvider::class)->willReturn($provider);
		$resolver = new AddressResolver(Server::get(BanMapper::class), $this->time(), $container);
		$throttler = $this->createMock(IThrottler::class);
		$throttler->method('isBypassListed')->willReturn($allowlisted);
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueBool')->willReturn(false);
		$context = new RequestContext();
		$cache = $this->addressCache(false);
		$guard = new AddressGuard(
			$config,
			$this->settings,
			$cache,
			$resolver,
			new RemoteAddressResolver($this->createMock(IRequest::class), $throttler, Server::get(ServerAddresses::class)),
			$context,
			$this->time(),
			new GuardTimer($this->createMock(ICacheFactory::class), $this->time()),
		);
		return [$guard, $context, $resolver];
	}

	private function addressCache(bool $available): AddressCache {
		$store = new \OC\Memcache\ArrayCache('ids-test-blocklist');
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn($available);
		$factory->method('isLocalCacheAvailable')->willReturn($available);
		$factory->method('createDistributed')->willReturn($store);
		$factory->method('createLocal')->willReturn($store);
		return new AddressCache($factory, Server::get(StateMapper::class));
	}

	private function time(): ITimeFactory {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(self::NOW);
		return $time;
	}
}
