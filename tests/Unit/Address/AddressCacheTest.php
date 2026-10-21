<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Address;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IAppConfig;
use OCP\ICacheFactory;
use Test\TestCase;

class AddressCacheTest extends TestCase {
	private const NOW = 1792490400;

	/** One store per kind, shared by every "web server" of a test */
	private ArrayCache $distributed;
	private ArrayCache $local;
	private int $appConfigVersion = 0;
	private int $versionReads = 0;

	protected function setUp(): void {
		parent::setUp();
		$this->versionReads = 0;
		$reads = &$this->versionReads;
		$this->distributed = new class('ids-test-redis', $reads) extends ArrayCache {
			public function __construct(
				string $prefix,
				private int &$reads,
			) {
				parent::__construct($prefix);
			}

			public function get($key) {
				if ($key === 'addr:v') {
					$this->reads++;
				}
				return parent::get($key);
			}
		};
		$this->local = new ArrayCache('ids-test-apcu');
	}

	public function testABlockOfOneAddressReplacesOnlyItsVerdict(): void {
		$cache = $this->cache();
		$blocked = SourceKey::fromIp('198.51.100.7');
		$other = SourceKey::fromIp('198.51.100.8');
		$cache->set($blocked, $this->ok(), self::NOW);
		$cache->set($other, $this->ok(), self::NOW);

		$this->cache()->refresh($blocked, $this->denied(), self::NOW);
		$this->assertTrue($cache->get($blocked)?->isDenied(self::NOW), 'Every web server sees the block');
		$this->assertNotNull($cache->get($other), 'Other verdicts stay cached');
	}

	public function testAStaleVerdictCannotOverwriteAFreshBlock(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$this->cache()->refresh($source, $this->denied(), self::NOW);
		// A request that resolved the address just before the block stores its old verdict.
		$this->cache()->set($source, $this->ok(), self::NOW);
		$this->assertTrue($this->cache()->get($source)?->isDenied(self::NOW));
	}

	public function testParallelChangesNeverEndOnAnOldVersion(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$first = $this->cache();
		$first->set($source, $this->ok(), self::NOW);
		// Two requests change the lists at the same time, each from what it read.
		$one = $this->cache();
		$two = $this->cache();
		$one->get($source);
		$two->get($source);
		$one->bump();
		$two->bump();
		$this->assertNull($this->cache()->get($source), 'The old verdict is gone after both');
	}

	public function testTheVersionIsReadOncePerRequest(): void {
		$cache = $this->cache();
		$cache->get(SourceKey::fromIp('198.51.100.7'));
		$cache->get(SourceKey::fromIp('198.51.100.8'));
		$cache->set(SourceKey::fromIp('198.51.100.8'), $this->ok(), self::NOW);
		$this->assertSame(1, $this->versionReads);
	}

	public function testALostVersionStartsAFreshOne(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$this->cache()->set($source, $this->ok(), self::NOW);
		$this->distributed->remove('addr:v');
		$this->assertNull($this->cache()->get($source), 'No old verdict comes back');
	}

	public function testIpv6VerdictsAreSharedByTheSlash64(): void {
		$this->cache()->set(SourceKey::fromIp('2001:db8:1:2::1'), $this->denied(), self::NOW);
		$this->assertTrue($this->cache()->get(SourceKey::fromIp('2001:db8:1:2:abcd::99'))?->isDenied(self::NOW), 'A privacy address of the same /64');
		$this->assertNull($this->cache()->get(SourceKey::fromIp('2001:db8:1:3::1')));
	}

	public function testVerdictsForOneIpv6AddressOnlyStayPerAddress(): void {
		$exit = SourceKey::fromIp('2001:db8:1:2::77');
		$neighbour = SourceKey::fromIp('2001:db8:1:2::78');
		$cache = $this->cache();
		$cache->set($exit, new Verdict(0, '', ['tor'], self::NOW + 300, true), self::NOW);
		$this->assertNull($this->cache()->get($neighbour), 'The neighbour does not get the Tor verdict');
		$second = $this->cache();
		$second->get($neighbour);
		$second->set($neighbour, new Verdict(0, '', [], self::NOW + 300, true), self::NOW);
		$this->assertSame(['tor'], $this->cache()->get($exit)?->attributes, 'Both are kept side by side');
		$this->assertSame([], $this->cache()->get($neighbour)?->attributes);

		$this->cache()->refresh(SourceKey::fromIp('2001:db8:1:2::'), new Verdict(self::NOW + 600, 'R', [], self::NOW + 600, true), self::NOW);
		$this->assertNull($this->cache()->get($exit), 'A block of the /64 drops every address in it');
		$this->assertNull($this->cache()->get($neighbour));
	}

	public function testWithOnlyALocalCacheAChangeReachesEveryServerThroughAppConfig(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$server = $this->cache('local');
		$this->assertFalse($server->isDistributed());
		$server->set($source, $this->ok(), self::NOW);
		$before = $this->appConfigVersion;
		$this->cache('local')->refresh($source, $this->denied(), self::NOW);
		$this->assertNotSame($before, $this->appConfigVersion, 'The version in app config changed');
	}

	public function testApcuHandedOutAsTheDistributedCacheIsLocal(): void {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn(true);
		$factory->method('isLocalCacheAvailable')->willReturn(true);
		$factory->method('createDistributed')->willReturn(new ArrayCache('a'));
		$factory->method('createLocal')->willReturn(new ArrayCache('b'));
		$this->assertFalse((new AddressCache($factory, $this->appConfig()))->isDistributed());
	}

	/**
	 * A fresh instance, as a new request on any web server would have.
	 *
	 * @param 'distributed'|'local' $kind
	 */
	private function cache(string $kind = 'distributed'): AddressCache {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn($kind === 'distributed');
		$factory->method('isLocalCacheAvailable')->willReturn(true);
		$factory->method('createDistributed')->willReturn($this->distributed);
		$factory->method('createLocal')->willReturn($this->local);
		return new AddressCache($factory, $this->appConfig());
	}

	private function appConfig(): IAppConfig {
		$appConfig = $this->createMock(IAppConfig::class);
		$appConfig->method('getValueInt')->willReturnCallback(fn (): int => $this->appConfigVersion);
		$appConfig->method('setValueInt')->willReturnCallback(function (string $app, string $key, int $value): bool {
			$this->appConfigVersion = $value;
			return true;
		});
		return $appConfig;
	}

	private function ok(): Verdict {
		return new Verdict(0, '', [], self::NOW + 300);
	}

	private function denied(): Verdict {
		return new Verdict(self::NOW + 3600, 'K7Q2-MPXA', [], self::NOW + 3600);
	}
}
