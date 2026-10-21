<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\OpenMetrics;

use Generator;
use OCA\IntrusionDetection\Db\BanMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\OpenMetrics\IMetricFamily;
use OCP\OpenMetrics\Metric;
use OCP\OpenMetrics\MetricType;
use Override;

/**
 * Blocks in force now, by scope (a single address or a network) and
 * escalation level.
 */
class BansActiveMetric implements IMetricFamily {
	public function __construct(
		private readonly BanMapper $bans,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	#[Override]
	public function name(): string {
		return 'intrusion_bans_active';
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
		return 'Blocked addresses and networks, by scope and escalation level';
	}

	#[Override]
	public function metrics(): Generator {
		$rows = $this->bans->countActiveByScopeAndLevel($this->timeFactory->getTime());
		if ($rows === []) {
			yield new Metric(0);
			return;
		}
		foreach ($rows as $row) {
			yield new Metric($row['count'], ['scope' => $row['scope'], 'level' => (string)$row['level']]);
		}
	}
}
