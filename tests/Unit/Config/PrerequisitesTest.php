<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Config;

use OCA\IntrusionDetection\Config\Prerequisites;
use OCP\ICacheFactory;
use OCP\IConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class PrerequisitesTest extends TestCase {
	public static function caches(): array {
		return [
			'none' => ['', '', false, false],
			'APCu only: core hands it out as the distributed cache too' => ['\\OC\\Memcache\\APCu', '', true, false],
			'APCu configured as distributed' => ['\\OC\\Memcache\\APCu', 'OC\\Memcache\\APCu', true, false],
			'Redis' => ['\\OC\\Memcache\\APCu', '\\OC\\Memcache\\Redis', true, true],
			'Memcached' => ['', '\\OC\\Memcache\\Memcached', true, true],
		];
	}

	#[DataProvider('caches')]
	public function testADistributedCacheIsOnlyOneThatIsConfiguredAsSuch(string $local, string $distributed, bool $memoryCache, bool $isDistributed): void {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isLocalCacheAvailable')->willReturn($local !== '');
		$factory->method('isAvailable')->willReturn($local !== '' || $distributed !== '');
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturnCallback(static fn (string $key, string $default = ''): string => $key === 'memcache.distributed' ? $distributed : $default);
		$prerequisites = new Prerequisites($factory, $config);
		$this->assertSame($memoryCache, $prerequisites->hasMemoryCache());
		$this->assertSame($isDistributed, $prerequisites->hasDistributedCache());
	}
}
