<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\OpenMetrics;

use Generator;
use OCA\IntrusionDetection\Lockdown\LockdownState;
use OCP\OpenMetrics\IMetricFamily;
use OCP\OpenMetrics\Metric;
use OCP\OpenMetrics\MetricType;
use Override;

/**
 * Whether lockdown mode is on (concept section 17.4). One app config read.
 */
class LockdownActiveMetric implements IMetricFamily {
	public function __construct(
		private readonly LockdownState $lockdown,
	) {
	}

	#[Override]
	public function name(): string {
		return 'intrusion_lockdown_active';
	}

	#[Override]
	public function type(): MetricType {
		return MetricType::gauge;
	}

	#[Override]
	public function unit(): string {
		return '';
	}

	#[Override]
	public function help(): string {
		return 'Whether lockdown mode is on (1) or off (0)';
	}

	#[Override]
	public function metrics(): Generator {
		yield new Metric($this->lockdown->isActive());
	}
}
