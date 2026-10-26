<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\BackgroundJob\PendingCounts;
use OCA\IntrusionDetection\Blocklist\BlocklistFactsProvider;
use OCA\IntrusionDetection\Blocklist\BlocklistMatches;
use OCA\IntrusionDetection\Blocklist\Db\BlocklistRangeMapper;
use OCA\IntrusionDetection\Blocklist\Db\BlocklistStatMapper;
use OCA\IntrusionDetection\Blocklist\ListState;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Blocklist\StateStore;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Cache\CountBuffer;
use OCA\IntrusionDetection\Cache\KeyLock;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch\BlocklistMatch;
use OCA\IntrusionDetection\Check\Checks\ManualBlock\ManualBlock;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\UserDailyMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Detection\DetectionAccounts;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\DetectionHits;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\Guard\AddressGuard;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\State\AppState;
use OCA\IntrusionDetection\Tests\Unit\Cache\ClockedCache;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\IMemcache;
use OCP\IRequest;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * The rows many requests would rewrite at once: a failure of a targeted
 * account, a blocklist match on a verdict miss and a merged detection hit
 * write them only with the flush when a memory cache keeps the counts
 * ({@see CountBuffer}). Queries are counted with and without the cache.
 */
#[Group('DB')]
class HotWritesCostTest extends LoginFailureTestCase {
	/** A minute start */
	private const NOW = 1792625400;

	private int $now = self::NOW;
	private ?IMemcache $cache = null;
	private ?CountBuffer $buffer = null;
	/** @var array<string, FailedLoginStats|BlocklistMatches|DetectionHits> the owners of the counts, by class */
	private array $owners = [];

	public function testAFailedLoginOfAnAccountWritesNoCountRow(): void {
		$alice = $this->user('ids-hot-alice')->getUID();
		$this->failLogin('203.0.113.5', $alice);
		$direct = $this->queries(fn () => $this->failLogin('203.0.113.6', $alice));

		$this->cache = new ClockedCache(fn (): int => $this->now);
		$this->failLogin('203.0.113.5', $alice);
		$buffered = $this->queries(fn () => $this->failLogin('203.0.113.7', $alice));
		$this->assertSame($direct - 2, $buffered, 'No read and no write of the day\'s row');
		$this->assertSame(2, $this->failedLogins($alice), 'The cached failures wait for the flush');
		$this->assertSame(4, $this->failedLoginStats()->forUser($alice, new \DateTimeZone('UTC'))['total'], 'The page adds them');

		$this->now += CountBuffer::PERIOD + CountBuffer::SETTLE;
		$flush = $this->queries(fn () => $this->buffer()->flush($this->writers()));
		$this->assertSame(2, $flush, 'One read and one write for the minute');
		$this->assertSame(4, $this->failedLogins($alice));
	}

	public function testAVerdictMissCountsListMatchesInTheCache(): void {
		$this->settingsEditor()->setMode(BlocklistMatch::ID, Mode::Protect);
		$this->settingsEditor()->setGlobal(GlobalSettings::BLOCKLIST_SOURCES, json_encode([
			['id' => 'watch', 'url' => 'https://lists.example.org/watch.txt', 'purpose' => 'deny', 'mode' => 'observe', 'enabled' => true],
			['id' => 'cloud', 'url' => 'https://lists.example.org/cloud.txt', 'purpose' => 'hosting', 'enabled' => true],
		]));
		$this->load('watch', ['203.0.113.0/25']);
		$this->load('cloud', ['203.0.113.0/24']);
		$guard = $this->guard();
		$guard->decisionFor('203.0.113.1');
		$direct = $this->queries(fn () => $guard->decisionFor('203.0.113.2'));

		$this->cache = new ClockedCache(fn (): int => $this->now);
		$guard->decisionFor('203.0.113.3');
		$buffered = $this->queries(fn () => $guard->decisionFor('203.0.113.4'));
		$this->assertSame($direct - 4, $buffered, 'Two matched lists, each without a read and a write of its row');

		$this->now += CountBuffer::PERIOD + CountBuffer::SETTLE;
		$this->buffer()->flush($this->writers());
		$row = Server::get(BlocklistStatMapper::class)->find('watch', gmdate('Y-m-d', self::NOW));
		$this->assertSame(4, $row['matches'] ?? null);
		$this->assertSame(['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4'], $row['sample'] ?? null);
	}

	public function testMoreWebServersThanAddressesKeptOnceWriteNothingOnAVerdictMiss(): void {
		$guard = $this->guard();
		$this->cache = new ClockedCache(fn (): int => $this->now);
		$_SERVER['SERVER_ADDR'] = '10.0.0.1';
		$guard->decisionFor('192.0.2.1');
		$steady = $this->queries(fn () => $guard->decisionFor('192.0.2.2'));
		$costs = [];
		for ($round = 0; $round < 2; $round++) {
			for ($node = 1; $node <= 20; $node++) {
				$_SERVER['SERVER_ADDR'] = '10.0.0.' . $node;
				$costs[$round][] = $this->queries(fn () => $guard->decisionFor('192.0.2.' . (10 + $round * 20 + $node)));
			}
		}
		unset($_SERVER['SERVER_ADDR']);
		$this->assertSame(array_fill(0, 19, $steady + 4), array_slice($costs[0], 1), 'A new web server reads its row, stores it (an update that finds none, then the insert) and reads the others to forget quiet ones, once');
		$this->assertSame(array_fill(0, 20, $steady), $costs[1], 'then its misses cost nothing more, with 20 web servers');
		$this->assertFalse($this->appConfig->hasKey('intrusion_detection', 'server_addresses'), 'The app config is not written');
		$this->assertCount(20, Server::get(AppState::class)->getPrefixed(ServerAddresses::STATE_PREFIX));
	}

	public function testAMergedHitWithNothingNewWritesNoRow(): void {
		$service = $this->detectionService();
		$mode = new ModeState(Mode::Protect, Mode::Protect);
		$draft = new DetectionDraft(ManualBlock::ID, SourceKey::fromIp('198.51.100.7'), merge: DetectionDraft::MERGE_SOURCE);
		$service->record($draft, $mode);
		$direct = $this->queries(fn () => $service->record($draft, $mode));

		$this->cache = new ClockedCache(fn (): int => $this->now);
		$draft = new DetectionDraft(ManualBlock::ID, SourceKey::fromIp('198.51.100.8'), merge: DetectionDraft::MERGE_SOURCE);
		[$detection] = $service->record($draft, $mode);
		$this->now += 10;
		$buffered = $this->queries(fn () => $service->record($draft, $mode));
		$this->assertSame($direct - 1, $buffered, 'The merge target is read, the row is not written');
		$this->now += 10;
		$service->record($draft, $mode);
		$mapper = Server::get(DetectionMapper::class);
		$this->assertSame(1, $mapper->findById((string)$detection->getId())->getHits());

		$this->now += DetectionHits::REFRESH;
		$this->assertSame($direct, $this->queries(fn () => $service->record($draft, $mode)), 'A row last written a minute ago is written again');
		$stored = $mapper->findById((string)$detection->getId());
		$this->assertSame(self::NOW + 20 + DetectionHits::REFRESH, $stored->getLastSeenAt());
		$this->assertSame(4, $stored->getHits(), 'The row write adds the hits counted meanwhile');

		$this->now += CountBuffer::PERIOD + CountBuffer::SETTLE;
		$this->buffer()->flush($this->writers());
		$stored = $mapper->findById((string)$detection->getId());
		$this->assertSame(4, $stored->getHits(), 'The flush adds none of them again');
		$this->assertSame(self::NOW + 20 + DetectionHits::REFRESH, $stored->getLastSeenAt(), 'The flush never moves the last seen time back');
	}

	#[\Override]
	protected function failedLoginStats(): FailedLoginStats {
		return $this->owner(FailedLoginStats::class, fn (): FailedLoginStats => new FailedLoginStats(Server::get(UserDailyMapper::class), $this->appSettings(), $this->time(), $this->buffer()));
	}

	private function queries(\Closure $work): int {
		$before = self::executed();
		$work();
		return self::executed() - $before;
	}

	private static function executed(): int {
		return (int)Server::get(IDBConnection::class)->getInner()->getStats()['executed'];
	}

	private function failedLogins(string $uid): int {
		return (int)(Server::get(UserDailyMapper::class)->find($uid, intdiv(self::NOW, 86400) * 86400)['failed_logins'] ?? 0);
	}

	/**
	 * @template T of FailedLoginStats|BlocklistMatches|DetectionHits
	 * @param class-string<T> $class
	 * @param \Closure(): T $make
	 * @return T
	 */
	private function owner(string $class, \Closure $make): object {
		/** @var T */
		return $this->owners[$class] ??= $make();
	}

	/**
	 * A buffer whose cache the test switches on, with the owners built here.
	 */
	private function buffer(): CountBuffer {
		if ($this->buffer === null) {
			$test = $this;
			$caches = new class($test) extends Caches {
				public function __construct(
					private readonly HotWritesCostTest $test,
				) {
				}

				#[\Override]
				public function shared(string $namespace): ?IMemcache {
					return $this->test->cache();
				}
			};
			$this->buffer = new CountBuffer($caches, $this->time(), new NullLogger(), Server::get(Fingerprinter::class));
		}
		return $this->buffer;
	}

	/**
	 * @return list<\Closure(): bool>
	 */
	private function writers(): array {
		return array_values(array_map(static fn (FailedLoginStats|BlocklistMatches|DetectionHits $owner): \Closure => $owner->writeCounts(...), $this->owners));
	}

	public function cache(): ?IMemcache {
		return $this->cache;
	}

	private function detectionService(): DetectionService {
		$hits = $this->owner(DetectionHits::class, fn (): DetectionHits => new DetectionHits(Server::get(DetectionMapper::class), $this->buffer()));
		return new DetectionService(
			Server::get(DetectionMapper::class),
			Server::get(CheckRegistry::class),
			$this->checkSettings(),
			$this->time(),
			Server::get(RiskScorer::class),
			Server::get(DetectionAccounts::class),
			Server::get(DetectionTotals::class),
			new KeyLock(FixedCaches::none()),
			Server::get(Fingerprinter::class),
			$hits,
		);
	}

	/**
	 * @param list<string> $cidrs
	 */
	private function load(string $id, array $cidrs): void {
		$ranges = RangeCodec::merge(array_map(static fn (string $c): string => RangeCodec::parseCompact($c), $cidrs));
		Server::get(BlocklistRangeMapper::class)->writeVersion($id, 3, $ranges);
		Server::get(StateStore::class)->save($id, new ListState(version: 3, ranges: count($ranges)));
	}

	private function guard(): AddressGuard {
		$addressCache = new AddressCache(new FixedCaches(new ArrayCache('ids-hot-writes')), Server::get(AppState::class));
		$matches = $this->owner(BlocklistMatches::class, fn (): BlocklistMatches => new BlocklistMatches(Server::get(BlocklistStatMapper::class), $this->buffer()));
		$provider = new BlocklistFactsProvider(
			Server::get(SourceRepository::class),
			Server::get(StateStore::class),
			Server::get(BlocklistRangeMapper::class),
			$matches,
			$this->appSettings(),
			$this->checkSettings(),
			$addressCache,
			$this->time(),
			Server::get(LoggerInterface::class),
		);
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturn($provider);
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueBool')->willReturn(false);
		$owners = $this->createMock(ContainerInterface::class);
		$owners->method('get')->willReturnCallback(fn (string $id): ?object => $this->owners[$id] ?? null);
		return new AddressGuard(
			$config,
			$this->appSettings(),
			$addressCache,
			new AddressResolver(Server::get(BanMapper::class), $this->time(), $container),
			new RemoteAddressResolver($this->createMock(IRequest::class), Server::get(IThrottler::class), new ServerAddresses(Server::get(AppState::class), new FixedCaches(null, new ClockedCache(fn (): int => $this->now)), $this->time())),
			new RequestContext(),
			$this->time(),
			new GuardTimer(FixedCaches::none(), $this->time()),
			new PendingCounts($this->buffer(), $owners),
		);
	}

	private function time(): ITimeFactory {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		return $time;
	}
}
