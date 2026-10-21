<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\OpenMetrics;

use OCA\IntrusionDetection\Blocklist\BlocklistSource;
use OCA\IntrusionDetection\Blocklist\ListFormat;
use OCA\IntrusionDetection\Blocklist\ListState;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Blocklist\StateStore;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\OpenMetrics\BlocklistRangesMetric;
use OCA\IntrusionDetection\OpenMetrics\DetectionsMetric;
use OCA\IntrusionDetection\OpenMetrics\GuardSecondsMetric;
use OCA\IntrusionDetection\OpenMetrics\LearningModeMetric;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCP\ICache;
use OCP\ICacheFactory;
use OCP\OpenMetrics\Metric;
use OCP\OpenMetrics\MetricValue;
use Test\TestCase;

/**
 * The exporters that read no table, and the cache of the detections total.
 * The others are tested against the database in OpenMetricsTest.
 */
class MetricsTest extends TestCase {
	/**
	 * @return list<Metric>
	 */
	private static function metrics(\OCP\OpenMetrics\IMetricFamily $family): array {
		return iterator_to_array($family->metrics(), false);
	}

	public function testTheDetectionsTotalIsCachedForAMinute(): void {
		$stored = null;
		$cache = $this->createMock(ICache::class);
		$cache->method('get')->willReturnCallback(static function () use (&$stored) {
			return $stored;
		});
		$cache->expects($this->once())->method('set')->willReturnCallback(static function (string $key, mixed $value, int $ttl) use (&$stored): bool {
			TestCase::assertSame(DetectionsMetric::CACHE_TTL, $ttl);
			$stored = $value;
			return true;
		});
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('createLocal')->willReturn($cache);
		$totals = $this->createMock(DetectionTotals::class);
		$totals->expects($this->once())->method('totals')->willReturn([['check' => 'trap_url', 'severity' => 'low', 'enforced' => true, 'count' => 7]]);
		$metric = new DetectionsMetric($totals, $factory);

		foreach ([1, 2] as $_) {
			$metrics = self::metrics($metric);
			$this->assertCount(1, $metrics);
			$this->assertSame(7, $metrics[0]->value);
			$this->assertSame(['check' => 'trap_url', 'severity' => 'low', 'enforced' => 'true'], $metrics[0]->labels);
		}
	}

	public function testGuardTimeIsInSecondsAndNotANumberWithoutMeasurements(): void {
		$timer = $this->createMock(GuardTimer::class);
		$timer->method('summary')->with(1)->willReturnOnConsecutiveCalls(['samples' => 3, 'averageMicroseconds' => 42.0, 'maxMicroseconds' => 120], null);
		$metric = new GuardSecondsMetric($timer);

		$measured = self::metrics($metric);
		$this->assertSame([['stat' => 'avg'], ['stat' => 'max']], array_map(static fn (Metric $m): array => $m->labels, $measured));
		$this->assertEqualsWithDelta(0.000042, $measured[0]->value, 1e-12);
		$this->assertEqualsWithDelta(0.00012, $measured[1]->value, 1e-12);

		$unmeasured = self::metrics($metric);
		$this->assertSame(MetricValue::NOT_A_NUMBER, $unmeasured[0]->value);
		$this->assertSame(MetricValue::NOT_A_NUMBER, $unmeasured[1]->value);
	}

	public function testLearningMode(): void {
		$settings = $this->createMock(Settings::class);
		$settings->method('isLearning')->willReturnOnConsecutiveCalls(true, false);
		$metric = new LearningModeMetric($settings);
		$this->assertTrue(self::metrics($metric)[0]->value);
		$this->assertFalse(self::metrics($metric)[0]->value);
	}

	public function testBlocklistRangesOfEnabledListsWithADownload(): void {
		$list = static fn (string $id, string $purpose): BlocklistSource => new BlocklistSource($id, $id, 'https://lists.example.org/' . $id, ListFormat::Cidr, $purpose, null, true, null, false);
		$sources = $this->createMock(SourceRepository::class);
		$sources->method('enabled')->willReturn([$list('spamhaus_drop', BlocklistSource::PURPOSE_DENY), $list('tor_exits', BlocklistSource::PURPOSE_TOR), $list('never_synced', BlocklistSource::PURPOSE_DENY)]);
		$states = $this->createMock(StateStore::class);
		$states->method('all')->willReturn([
			'spamhaus_drop' => new ListState(version: 3, ranges: 1200),
			'tor_exits' => new ListState(version: 1, ranges: 800),
			'never_synced' => new ListState(),
			'disabled_list' => new ListState(version: 2, ranges: 99),
		]);
		$metrics = self::metrics(new BlocklistRangesMetric($sources, $states));
		$this->assertSame([[1200, ['list' => 'spamhaus_drop']], [800, ['list' => 'tor_exits']]], array_map(static fn (Metric $m): array => [$m->value, $m->labels], $metrics));

		$none = $this->createMock(SourceRepository::class);
		$none->method('enabled')->willReturn([]);
		$this->assertSame([0], array_map(static fn (Metric $m): mixed => $m->value, self::metrics(new BlocklistRangesMetric($none, $states))));
	}
}
