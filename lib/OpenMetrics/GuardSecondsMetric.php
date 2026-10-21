<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\OpenMetrics;

use Generator;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCP\OpenMetrics\IMetricFamily;
use OCP\OpenMetrics\Metric;
use OCP\OpenMetrics\MetricType;
use OCP\OpenMetrics\MetricValue;
use Override;

/**
 * The time the request guards add to a request, average and maximum of the
 * sampled requests in the current hour, as measured by {@see GuardTimer}.
 * Not a number while nothing was measured, e.g. without a memory cache.
 */
class GuardSecondsMetric implements IMetricFamily {
	public function __construct(
		private readonly GuardTimer $timer,
	) {
	}

	#[Override]
	public function name(): string {
		return 'intrusion_guard_seconds';
	}

	#[Override]
	public function type(): MetricType {
		return MetricType::gauge;
	}

	#[Override]
	public function unit(): string {
		return 'seconds';
	}

	#[Override]
	public function help(): string {
		return 'Time the request guards add to a request in the current hour';
	}

	#[Override]
	public function metrics(): Generator {
		$summary = $this->timer->summary(1);
		yield new Metric($summary === null ? MetricValue::NOT_A_NUMBER : $summary['averageMicroseconds'] / 1e6, ['stat' => 'avg']);
		yield new Metric($summary === null ? MetricValue::NOT_A_NUMBER : $summary['maxMicroseconds'] / 1e6, ['stat' => 'max']);
	}
}
