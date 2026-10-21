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
use OCA\IntrusionDetection\Blocklist\BlocklistFactsProvider;
use OCA\IntrusionDetection\Blocklist\ListState;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Blocklist\StateStore;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\BlocklistRangeMapper;
use OCA\IntrusionDetection\Db\BlocklistStatMapper;
use OCA\IntrusionDetection\Guard\AddressGuard;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ICacheFactory;
use OCP\IConfig;
use OCP\IRequest;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The address check with a network list of 100 000 ranges loaded (concept
 * section 19.1): the hosting and Tor attributes come from the same verdict
 * as blocks, so a warm request costs the same two cache gets as without
 * lists, and a cold one one indexed range query more.
 */
#[Group('DB')]
class RiskyNetworkBenchmarkTest extends IntegrationTestCase {
	private const RANGES = 100000;
	private const WARM = 10000;
	private const COLD = 500;
	/** The whole guard budget is 100 µs per request */
	private const WARM_BUDGET_US = 20;
	/** Without a memory cache every request resolves: < 2 ms */
	private const COLD_BUDGET_US = 2000;

	public function testTheAddressCheckStaysWithinBudgetWithAHundredThousandRanges(): void {
		$settings = Server::get(Settings::class);
		$settings->setGlobal(GlobalSettings::BLOCKLIST_SOURCES, json_encode([
			['id' => 'cloud', 'url' => 'https://lists.example.org/cloud.txt', 'purpose' => 'hosting', 'enabled' => true],
		]));
		$ranges = [];
		for ($i = 0; $i < self::RANGES; $i++) {
			// Every other address of 20.0.0.0/8, so that no two ranges merge.
			$ranges[] = RangeCodec::parseCompact(long2ip(ip2long('20.0.0.0') + 2 * $i));
		}
		Server::get(BlocklistRangeMapper::class)->writeVersion('cloud', 1, $ranges);
		Server::get(StateStore::class)->save('cloud', new ListState(version: 1, ranges: self::RANGES));
		$this->assertSame(self::RANGES, Server::get(BlocklistRangeMapper::class)->countVersion('cloud', 1));

		$listed = long2ip(ip2long('20.0.0.0') + 2 * 54321);
		$warmGuard = $this->guard(true);
		$this->assertNull($warmGuard->decisionFor($listed));
		$this->assertSame(['hosting', 'net:cloud'], $this->context->verdict()?->attributes, 'The verdict carries the attributes');
		$warm = $this->measure(fn () => $warmGuard->decisionFor($listed), self::WARM);

		$coldGuard = $this->guard(false);
		$i = 0;
		$cold = $this->measure(function () use ($coldGuard, &$i): void {
			// Half on the list, half just next to a listed address.
			$coldGuard->decisionFor(long2ip(ip2long('20.0.0.0') + 2 * (($i * 197) % self::RANGES) + ($i % 2)));
			$i++;
		}, self::COLD);
		$withoutList = $this->guard(false, false);
		$plain = $this->measure(fn () => $withoutList->decisionFor('20.0.0.1'), self::COLD);

		fwrite(STDERR, sprintf(
			"\n[risky_network] address check with %d network ranges: warm (memory cache) %.2f µs per request; cold (resolved from the database, as without a memory cache) %.1f µs with the list, %.1f µs without it\n",
			self::RANGES,
			$warm,
			$cold,
			$plain,
		));
		$this->assertLessThan(self::WARM_BUDGET_US, $warm);
		$this->assertLessThan(self::COLD_BUDGET_US, $cold);
	}

	private RequestContext $context;

	/**
	 * @param bool $cached whether a memory cache keeps the verdicts
	 * @param bool $withList whether the network list is enabled
	 */
	private function guard(bool $cached, bool $withList = true): AddressGuard {
		if (!$withList) {
			Server::get(Settings::class)->setGlobal(GlobalSettings::BLOCKLIST_SOURCES, '[]');
		}
		$store = new ArrayCache();
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn($cached);
		$factory->method('isLocalCacheAvailable')->willReturn($cached);
		$factory->method('createDistributed')->willReturn($store);
		$factory->method('createLocal')->willReturn($store);
		$addressCache = new AddressCache($factory, $this->appConfig);
		$settings = Server::get(Settings::class);
		$provider = new BlocklistFactsProvider(
			new SourceRepository($settings, Server::get(\OCA\IntrusionDetection\Crypto\Fingerprinter::class)),
			Server::get(StateStore::class),
			Server::get(BlocklistRangeMapper::class),
			Server::get(BlocklistStatMapper::class),
			$settings,
			$addressCache,
			Server::get(ITimeFactory::class),
			Server::get(LoggerInterface::class),
		);
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturn($provider);
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueBool')->willReturn(false);
		$this->context = new RequestContext();
		return new AddressGuard(
			$config,
			$settings,
			$addressCache,
			new AddressResolver(Server::get(BanMapper::class), Server::get(ITimeFactory::class), $container),
			new RemoteAddressResolver($this->createMock(IRequest::class), Server::get(IThrottler::class)),
			$this->context,
			Server::get(ITimeFactory::class),
			new GuardTimer($this->createMock(ICacheFactory::class), Server::get(ITimeFactory::class)),
		);
	}

	/**
	 * @return float µs per call
	 */
	private function measure(\Closure $call, int $times): float {
		$start = hrtime(true);
		for ($n = 0; $n < $times; $n++) {
			$call();
		}
		return (hrtime(true) - $start) / 1000 / $times;
	}
}
