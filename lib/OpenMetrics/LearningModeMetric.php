<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\OpenMetrics;

use Generator;
use OCA\IntrusionDetection\Config\Settings;
use OCP\OpenMetrics\IMetricFamily;
use OCP\OpenMetrics\Metric;
use OCP\OpenMetrics\MetricType;
use Override;

/**
 * Whether learning mode is on: every check observes instead of acting.
 */
class LearningModeMetric implements IMetricFamily {
	public function __construct(
		private readonly Settings $settings,
	) {
	}

	#[Override]
	public function name(): string {
		return 'intrusion_learning_mode';
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
		return 'Whether learning mode is on (1) or off (0)';
	}

	#[Override]
	public function metrics(): Generator {
		yield new Metric($this->settings->isLearning());
	}
}
