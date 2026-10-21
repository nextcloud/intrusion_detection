<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\DetectionMapper;

/**
 * How many detections were made since the app was installed, per check,
 * severity and enforcement: the detections still kept, plus a running total
 * of those deleted after their retention, which is kept in the app config.
 *
 * Counting this way costs one grouped count over the detections table and
 * no write on the path that records a detection.
 */
class DetectionTotals {
	public function __construct(
		private readonly DetectionMapper $mapper,
		private readonly Settings $settings,
	) {
	}

	/**
	 * Delete the detections created before a time, and add them to the
	 * running total first.
	 *
	 * @return int how many were deleted
	 */
	public function deleteCreatedBefore(int $before): int {
		$counts = $this->mapper->countByLabels($before);
		if ($counts === []) {
			return 0;
		}
		$deleted = $this->mapper->deleteCreatedBefore($before);
		$retired = $this->retired();
		foreach ($counts as $key => $count) {
			$retired[$key] = ($retired[$key] ?? 0) + $count;
		}
		$this->settings->setGlobal(GlobalSettings::DETECTIONS_RETIRED, $retired);
		return $deleted;
	}

	/**
	 * Every detection since installation, by check, severity and enforcement.
	 *
	 * @return list<array{check: string, severity: string, enforced: bool, count: int}>
	 */
	public function totals(): array {
		$totals = $this->retired();
		foreach ($this->mapper->countByLabels() as $key => $count) {
			$totals[$key] = ($totals[$key] ?? 0) + $count;
		}
		ksort($totals);
		$rows = [];
		foreach ($totals as $key => $count) {
			$parts = explode('|', $key);
			if (count($parts) === 3) {
				$rows[] = ['check' => $parts[0], 'severity' => $parts[1], 'enforced' => $parts[2] === '1', 'count' => $count];
			}
		}
		return $rows;
	}

	/**
	 * @return array<string, int>
	 */
	private function retired(): array {
		$retired = [];
		foreach ($this->settings->getJson(GlobalSettings::DETECTIONS_RETIRED) as $key => $count) {
			if (is_string($key) && is_int($count) && $count > 0) {
				$retired[$key] = $count;
			}
		}
		return $retired;
	}
}
