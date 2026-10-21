<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\OpenMetrics;

use Generator;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCP\OpenMetrics\IMetricFamily;
use OCP\OpenMetrics\Metric;
use OCP\OpenMetrics\MetricType;
use Override;

/**
 * Requests waiting for a second administrator's approval, by kind.
 */
class ApprovalsPendingMetric implements IMetricFamily {
	public function __construct(
		private readonly ApprovalMapper $approvals,
	) {
	}

	#[Override]
	public function name(): string {
		return 'intrusion_approvals_pending';
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
		return 'Requests waiting for approval by a second administrator, by kind';
	}

	#[Override]
	public function metrics(): Generator {
		$counts = $this->approvals->countPendingByKind() + [Approval::KIND_ADMIN_GRANT => 0];
		ksort($counts);
		foreach ($counts as $kind => $count) {
			yield new Metric($count, ['kind' => (string)$kind]);
		}
	}
}
