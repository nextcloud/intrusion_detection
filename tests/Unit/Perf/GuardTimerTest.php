<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Perf;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ICacheFactory;
use Test\TestCase;

class GuardTimerTest extends TestCase {
	private function timer(bool $sampled, ArrayCache $cache): GuardTimer {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn(true);
		$factory->method('createDistributed')->willReturn($cache);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(1_800_000_000);
		return new class($factory, $time, $sampled) extends GuardTimer {
			public int $decisions = 0;

			public function __construct(
				ICacheFactory $factory,
				ITimeFactory $time,
				private readonly bool $sampled,
			) {
				parent::__construct($factory, $time);
			}

			#[\Override]
			public function sample(): bool {
				$this->decisions++;
				return $this->sampled;
			}
		};
	}

	public function testAllGuardsOfASampledRequestAreRecordedOnceTogether(): void {
		$cache = new ArrayCache();
		$timer = $this->timer(true, $cache);
		foreach ([1, 2, 3] as $guard) {
			$start = $timer->start();
			$this->assertNotNull($start);
			usleep(1000);
			$timer->stop($start);
		}
		$this->assertNull($timer->summary(1), 'Nothing is written before the request ends');

		$timer->finish();
		$summary = $timer->summary(1);
		$this->assertSame(1, $summary['samples'], 'One request, one sample');
		$this->assertGreaterThanOrEqual(3000, $summary['averageMicroseconds'], 'The time of all three guards');
		$this->assertSame(1, $timer->decisions, 'The first guard decides for the whole request');

		$timer->finish();
		$this->assertSame(1, $timer->summary(1)['samples'], 'Recorded only once');
	}

	public function testARequestThatIsNotSampledCostsNothing(): void {
		$cache = new ArrayCache();
		$timer = $this->timer(false, $cache);
		$this->assertNull($timer->start());
		$timer->stop(null);
		$this->assertNull($timer->start());
		$timer->finish();
		$this->assertNull($timer->summary(1));
		$this->assertSame(1, $timer->decisions);
	}

	public function testAViewReadsTheEarlierHoursOncePerHour(): void {
		$cache = new class() extends ArrayCache {
			public int $gets = 0;

			#[\Override]
			public function get($key) {
				$this->gets++;
				return parent::get($key);
			}
		};
		$timer = $this->timer(true, $cache);
		$hour = intdiv(1_800_000_000, 3600);
		$cache->set('gt:' . ($hour - 3) . ':n', 2);
		$cache->set('gt:' . ($hour - 3) . ':s', 400);
		$cache->set('gt:' . ($hour - 3) . ':m', 300);
		$timer->record(100_000);

		$this->assertSame(['samples' => 3, 'averageMicroseconds' => 500 / 3, 'maxMicroseconds' => 300], $timer->summary(24));
		$timer->record(200_000);
		$cache->gets = 0;
		$summary = $timer->summary(24);
		$this->assertSame(4, $summary['samples'], 'the current hour is read live');
		$this->assertSame(4, $cache->gets, 'the earlier hours come from one key');
	}
}
