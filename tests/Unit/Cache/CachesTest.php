<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Cache;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Cache\Caches;
use OCP\ICacheFactory;
use OCP\IConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class CachesTest extends TestCase {
	public static function configurations(): array {
		return [
			'none' => ['', '', false, false],
			'APCu only: core hands it out as the distributed cache too' => ['\\OC\\Memcache\\APCu', '', true, false],
			'APCu configured as distributed' => ['\\OC\\Memcache\\APCu', 'OC\\Memcache\\APCu', true, false],
			'Redis' => ['\\OC\\Memcache\\APCu', '\\OC\\Memcache\\Redis', true, true],
			'Redis for both' => ['\\OC\\Memcache\\Redis', '\\OC\\Memcache\\Redis', true, true],
			'Memcached' => ['', '\\OC\\Memcache\\Memcached', true, true],
		];
	}

	#[DataProvider('configurations')]
	public function testADistributedCacheIsOnlyOneThatIsConfiguredAsSuch(string $local, string $distributed, bool $memoryCache, bool $isDistributed): void {
		$caches = $this->caches($local, $distributed);
		$this->assertSame($memoryCache, $caches->isAvailable());
		$this->assertSame($isDistributed, $caches->isDistributed());
		$this->assertSame($isDistributed ? 'distributed' : ($memoryCache ? 'local' : 'none'), $caches->kind());
	}

	public function testTheSharedCacheIsTheDistributedOneOnlyWhenItIsReallyShared(): void {
		$this->assertSame('distributed', $this->caches('\\OC\\Memcache\\APCu', '\\OC\\Memcache\\Redis')->shared('x')?->get('from'));
		$this->assertSame('local', $this->caches('\\OC\\Memcache\\APCu', '')->shared('x')?->get('from'));
		$this->assertSame('distributed', $this->caches('', '\\OC\\Memcache\\APCu')->shared('x')?->get('from'), 'a local-only cache set as the distributed one is still used');
		$this->assertNull($this->caches('', '')->shared('x'));
	}

	public function testTheLocalCacheIsNeverTheDistributedOne(): void {
		$this->assertSame('local', $this->caches('\\OC\\Memcache\\APCu', '\\OC\\Memcache\\Redis')->local('x')?->get('from'));
		$this->assertNull($this->caches('', '\\OC\\Memcache\\Redis')->local('x'));
	}

	public function testEachNamespaceIsCreatedOnceAndClearedTogether(): void {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn(true);
		$factory->method('isLocalCacheAvailable')->willReturn(true);
		$factory->expects($this->exactly(2))->method('createLocal')->willReturnCallback(static fn (string $prefix): ArrayCache => new ArrayCache($prefix));
		$caches = new Caches($factory, $this->createMock(IConfig::class));

		$caches->shared('one')?->set('k', 1);
		$caches->shared('two')?->set('k', 2);
		$this->assertSame(1, $caches->shared('one')?->get('k'), 'the same cache within the process');
		$this->assertSame(2, $caches->shared('two')?->get('k'), 'namespaces do not share keys');

		$caches->clear();
		$this->assertNull($caches->shared('one')?->get('k'));
		$this->assertNull($caches->shared('two')?->get('k'));
	}

	public function testNamespacesAreUnderTheAppId(): void {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isLocalCacheAvailable')->willReturn(true);
		$factory->expects($this->once())->method('createLocal')->with('intrusion_detection-lock')->willReturn(new ArrayCache());
		(new Caches($factory, $this->createMock(IConfig::class)))->local('lock');
	}

	private function caches(string $local, string $distributed): Caches {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isLocalCacheAvailable')->willReturn($local !== '');
		$factory->method('isAvailable')->willReturn($local !== '' || $distributed !== '');
		$factory->method('createLocal')->willReturnCallback(static fn (): ArrayCache => self::marked('local'));
		$factory->method('createDistributed')->willReturnCallback(static fn (): ArrayCache => self::marked('distributed'));
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturnCallback(static fn (string $key, string $default = ''): string => $key === 'memcache.distributed' ? $distributed : $default);
		return new Caches($factory, $config);
	}

	private static function marked(string $from): ArrayCache {
		$cache = new ArrayCache();
		$cache->set('from', $from);
		return $cache;
	}
}
