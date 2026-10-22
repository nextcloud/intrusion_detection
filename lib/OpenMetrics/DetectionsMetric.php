<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\OpenMetrics;

use Generator;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCP\OpenMetrics\IMetricFamily;
use OCP\OpenMetrics\Metric;
use OCP\OpenMetrics\MetricType;
use Override;

/**
 * Detections since the app was installed, by check, severity and whether
 * Nextcloud acted on them, from the running totals ({@see DetectionTotals}),
 * which only ever grow. Cached for a minute, in the distributed cache when
 * there is one, so frequent scrapes from several servers cost nothing.
 */
class DetectionsMetric implements IMetricFamily {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'metrics';
	public const CACHE_TTL = 60;
	private const CACHE_KEY = 'detections_total';

	public function __construct(
		private readonly DetectionTotals $totals,
		private readonly Caches $caches,
	) {
	}

	#[Override]
	public function name(): string {
		return 'intrusion_detections_total';
	}

	#[Override]
	public function type(): MetricType {
		return MetricType::counter;
	}

	#[Override]
	public function unit(): string {
		return '';
	}

	#[Override]
	public function help(): string {
		return 'Detections since the app was installed, by check, severity and enforcement';
	}

	#[Override]
	public function metrics(): Generator {
		$cache = $this->caches->shared(self::CACHE);
		$rows = $cache?->get(self::CACHE_KEY);
		if (!is_array($rows)) {
			$rows = $this->totals->totals();
			$cache?->set(self::CACHE_KEY, $rows, self::CACHE_TTL);
		}
		if ($rows === []) {
			yield new Metric(0);
			return;
		}
		foreach ($rows as $row) {
			if (is_array($row) && isset($row['check'], $row['severity'], $row['enforced'], $row['count'])) {
				yield new Metric((int)$row['count'], [
					'check' => (string)$row['check'],
					'severity' => (string)$row['severity'],
					'enforced' => $row['enforced'] ? 'true' : 'false',
				]);
			}
		}
	}
}
