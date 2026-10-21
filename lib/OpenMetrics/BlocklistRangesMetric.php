<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\OpenMetrics;

use Generator;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Blocklist\StateStore;
use OCP\OpenMetrics\IMetricFamily;
use OCP\OpenMetrics\Metric;
use OCP\OpenMetrics\MetricType;
use Override;

/**
 * Address ranges in use per enabled list (blocklists and the hosting and Tor
 * lists), from the state of the last successful download. No query.
 */
class BlocklistRangesMetric implements IMetricFamily {
	public function __construct(
		private readonly SourceRepository $sources,
		private readonly StateStore $states,
	) {
	}

	#[Override]
	public function name(): string {
		return 'intrusion_blocklist_ranges';
	}

	#[Override]
	public function type(): MetricType {
		return MetricType::gauge;
	}

	#[Override]
	public function unit(): string {
		return 'ranges';
	}

	#[Override]
	public function help(): string {
		return 'Address ranges in use per enabled list';
	}

	#[Override]
	public function metrics(): Generator {
		$states = $this->states->all();
		$found = false;
		foreach ($this->sources->enabled() as $source) {
			$state = $states[$source->id] ?? null;
			if ($state?->version !== null) {
				$found = true;
				yield new Metric($state->ranges, ['list' => $source->id]);
			}
		}
		if (!$found) {
			yield new Metric(0);
		}
	}
}
