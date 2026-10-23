<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Admin;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Admin\CheckNames;
use OCA\IntrusionDetection\Admin\SetupProblems;
use OCA\IntrusionDetection\Admin\StatusService;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\StatsMapper;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class StatusServiceTest extends TestCase {
	private AppSettings&MockObject $settings;
	private LearningService&MockObject $learning;
	private GuardTimer&MockObject $timer;
	private SetupProblems&MockObject $setupProblems;
	private IL10N $l;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = $this->createMock(AppSettings::class);
		$this->settings->method('isEnabled')->willReturn(true);
		$this->learning = $this->createMock(LearningService::class);
		$this->timer = $this->createMock(GuardTimer::class);
		$this->setupProblems = $this->createMock(SetupProblems::class);
		$this->l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
	}

	/**
	 * @param class-string<StatusService> $class
	 */
	private function service(string $class = StatusService::class, ?Caches $cacheFactory = null, ?DetectionTotals $totals = null, ?StatsMapper $stats = null): StatusService {
		$registry = $this->createMock(CheckRegistry::class);
		$registry->method('configurable')->willReturn([]);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(1_790_000_000);
		return new $class(
			$this->settings,
			$this->createMock(CheckSettings::class),
			$registry,
			new CheckNames($registry),
			$this->learning,
			$this->createMock(Prerequisites::class),
			$this->createMock(BanMapper::class),
			$totals ?? $this->createMock(DetectionTotals::class),
			$stats ?? $this->createMock(StatsMapper::class),
			$this->timer,
			$time,
			$this->setupProblems,
			$cacheFactory ?? FixedCaches::none(),
		);
	}

	public function testASlowAddressCheckIsAProblem(): void {
		$this->timer->method('summary')->willReturn(['samples' => 40, 'averageMicroseconds' => 1500.0, 'maxMicroseconds' => 9000]);
		$status = $this->service()->status($this->l);
		$this->assertSame(['samples' => 40, 'averageMicroseconds' => 1500.0, 'maxMicroseconds' => 9000], $status['cost']);
		$this->assertSame(['slow_guards'], array_column($status['problems'], 'id'));
	}

	public function testAFastAddressCheckIsNoProblem(): void {
		$this->timer->method('summary')->willReturn(['samples' => 40, 'averageMicroseconds' => 31.04, 'maxMicroseconds' => 90]);
		$status = $this->service()->status($this->l);
		$this->assertSame(31.0, $status['cost']['averageMicroseconds'] ?? null);
		$this->assertSame([], $status['problems']);
	}

	public function testTheNumbersAreKeptForAMinutePerLanguageAndTheProblemsAreReadLive(): void {
		$cache = new ArrayCache();
		$factory = new FixedCaches($cache);
		$totals = $this->createMock(DetectionTotals::class);
		$totals->expects($this->exactly(2))->method('perCheck')->with(1_790_000_000 - 86400)->willReturn([]);
		$stats = $this->createMock(StatsMapper::class);
		$stats->expects($this->exactly(2))->method('accountsSince')->willReturn(4);
		$this->timer->method('summary')->willReturn(null);
		$this->setupProblems->expects($this->exactly(4))->method('problems')->willReturn([]);

		$first = $this->service(StatusService::class, $factory, $totals, $stats)->status($this->l);
		$this->assertSame(4, $first['last24h']['accounts']);
		$again = $this->service(StatusService::class, $factory, $totals, $stats)->status($this->l);
		$this->assertSame($first, $again, 'the second request counts nothing');

		$german = $this->createMock(IL10N::class);
		$german->method('getLanguageCode')->willReturn('de');
		$german->method('t')->willReturnArgument(0);
		$this->service(StatusService::class, $factory, $totals, $stats)->status($german);

		$this->learning->method('isActive')->willReturn(true);
		$learning = $this->service(StatusService::class, $factory, $totals, $stats)->status($this->l);
		$this->assertSame('learning', $learning['state'], 'the state is always read live');
		$this->assertSame(4, $learning['last24h']['accounts']);
	}

	public function testLearningState(): void {
		$this->learning->method('isActive')->willReturn(true);
		$this->learning->method('until')->willReturn(1_790_300_000);
		$this->learning->method('daysLeft')->willReturn(4);
		$service = $this->service();
		$this->assertSame('learning', $service->state());
		$this->assertSame(['active' => true, 'until' => 1_790_300_000, 'daysLeft' => 4, 'minDays' => 1, 'maxDays' => 30], $service->learning());
	}

	public function testTheSetupProblemsFollowASlowAddressCheck(): void {
		$this->timer->method('summary')->willReturn(['samples' => 40, 'averageMicroseconds' => 1500.0, 'maxMicroseconds' => 9000]);
		$this->setupProblems->method('problems')->willReturn([['id' => 'proxy', 'level' => 'warning', 'title' => 'Proxy', 'text' => 'Configure trusted proxies.', 'url' => null, 'urlLabel' => null]]);
		$this->assertSame(['slow_guards', 'proxy'], array_column($this->service()->status($this->l)['problems'], 'id'));
	}
}
