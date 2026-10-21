<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Db\StatsMapper;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IDateTimeZone;

/**
 * Detections per day for the overview chart: one entry per day, also for
 * days without any, split into enforced and observed and by category.
 *
 * Days follow the admin's time zone. The offset of today is used for the
 * whole range, so around a daylight saving change one hour may be counted
 * on the neighbouring day.
 *
 * @psalm-import-type IntrusionDetectionDailyStats from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionDay from ResponseDefinitions
 */
class DailyStats {
	public const MAX_DAYS = 90;

	public function __construct(
		private readonly DetectionTotals $totals,
		private readonly CheckNames $names,
		private readonly IDateTimeZone $dateTimeZone,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return IntrusionDetectionDailyStats
	 */
	public function days(int $days): array {
		$days = max(1, min(self::MAX_DAYS, $days));
		$now = $this->timeFactory->getTime();
		$timezone = $this->dateTimeZone->getTimeZone($now);
		$offset = $timezone->getOffset(new \DateTimeImmutable('@' . $now));
		$today = intdiv($now + $offset, StatsMapper::DAY);
		$first = $today - $days + 1;

		/** @var array<int, IntrusionDetectionDay> $buckets */
		$buckets = [];
		for ($bucket = $first; $bucket <= $today; $bucket++) {
			$start = $bucket * StatsMapper::DAY - $offset;
			$buckets[$bucket] = [
				'day' => (new \DateTimeImmutable('@' . $start))->setTimezone($timezone)->format('Y-m-d'),
				'start' => $start,
				'enforced' => 0,
				'observed' => 0,
				'categories' => [],
			];
		}

		foreach ($this->totals->perDay($first * StatsMapper::DAY - $offset, $offset) as $row) {
			if (!isset($buckets[$row['bucket']])) {
				continue;
			}
			$key = $row['enforced'] ? 'enforced' : 'observed';
			$category = $this->names->category($row['checkId'])->value;
			$buckets[$row['bucket']][$key] += $row['count'];
			$buckets[$row['bucket']]['categories'][$category] ??= ['enforced' => 0, 'observed' => 0];
			$buckets[$row['bucket']]['categories'][$category][$key] += $row['count'];
		}

		return ['days' => array_values($buckets), 'timezone' => $timezone->getName()];
	}
}
