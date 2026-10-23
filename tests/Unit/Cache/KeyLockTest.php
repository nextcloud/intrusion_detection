<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Cache;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Cache\KeyLock;
use Test\TestCase;

class KeyLockTest extends TestCase {
	private ArrayCache $cache;

	protected function setUp(): void {
		parent::setUp();
		$this->cache = new ArrayCache();
	}

	private function lock(): KeyLock {
		return new KeyLock(new FixedCaches($this->cache));
	}

	public function testTheWorkRunsUnderTheLockAndReleasesIt(): void {
		$key = 'ban/' . md5('4:198.51.100.7');
		$result = $this->lock()->run('ban', '4:198.51.100.7', function () use ($key): string {
			$this->assertNotNull($this->cache->get($key), 'held while the work runs');
			return 'done';
		});
		$this->assertSame('done', $result);
		$this->assertNull($this->cache->get($key), 'released');
	}

	public function testALockIsReleasedWhenTheWorkThrows(): void {
		try {
			$this->lock()->run('ban', 'x', static fn () => throw new \RuntimeException('boom'));
			$this->fail('The exception reaches the caller');
		} catch (\RuntimeException) {
		}
		$this->assertNull($this->cache->get('ban/' . md5('x')));
	}

	public function testWithoutAMemoryCacheTheWorkRunsUnlocked(): void {
		$this->assertSame(7, (new KeyLock(FixedCaches::none()))->run('ban', 'x', static fn (): int => 7));
	}

	public function testAStaleLockCostsOnePauseAndIsLeftAlone(): void {
		$key = 'detection/' . md5('merge');
		$this->cache->set($key, 'someone else', KeyLock::TTL);
		$ran = false;
		$start = hrtime(true);
		$this->lock()->run('detection', 'merge', function () use (&$ran): void {
			$ran = true;
		});
		$elapsed = (hrtime(true) - $start) / 1000;
		$this->assertTrue($ran, 'the work runs anyway');
		$this->assertGreaterThanOrEqual(KeyLock::PAUSE_US, $elapsed);
		$this->assertLessThan(KeyLock::PAUSE_US * 4, $elapsed, 'waits once, not twenty times');
		$this->assertSame('someone else', $this->cache->get($key), 'another request\'s lock is never removed');
	}

	public function testALockLastsSeconds(): void {
		$cache = $this->createMock(ArrayCache::class);
		$cache->expects($this->once())->method('add')->with('ban/' . md5('x'), 1, KeyLock::TTL)->willReturn(true);
		$cache->expects($this->once())->method('remove')->with('ban/' . md5('x'))->willReturn(true);
		(new KeyLock(new FixedCaches($cache)))->run('ban', 'x', static fn () => null);
		$this->assertLessThanOrEqual(10, KeyLock::TTL);
	}
}
