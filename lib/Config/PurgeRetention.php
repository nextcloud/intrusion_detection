<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\State\AppState;

/**
 * How many days the owners of detections, the login history and the
 * security changes keep their rows when they delete the older ones.
 *
 * It is the retention setting, except that a shorter retention applies only
 * DELAY after it was first seen: lowering it must not delete the evidence of
 * what happened before anyone read the alert about the change. A longer
 * retention applies at once.
 */
class PurgeRetention {
	/** Seconds a lowered retention waits before it deletes anything */
	public const DELAY = 7 * 86400;
	/** The retention applied last, and since when a lower one waits: JSON {days, loweredAt} */
	public const STATE = 'retention_applied';

	public function __construct(
		private readonly AppSettings $settings,
		private readonly AppState $state,
	) {
	}

	public function days(int $now): int {
		$wanted = $this->settings->retentionDays();
		$stored = json_decode($this->state->get(self::STATE) ?? '', true);
		$applied = is_array($stored) && is_int($stored['days'] ?? null) ? $stored['days'] : null;
		$loweredAt = is_array($stored) && is_int($stored['loweredAt'] ?? null) ? $stored['loweredAt'] : 0;

		if ($applied === null || $wanted >= $applied) {
			if ($applied !== $wanted || $loweredAt !== 0) {
				$this->store($wanted, 0);
			}
			return $wanted;
		}
		if ($loweredAt === 0) {
			$this->store($applied, $now);
			return $applied;
		}
		if ($now - $loweredAt >= self::DELAY) {
			$this->store($wanted, 0);
			return $wanted;
		}
		return $applied;
	}

	private function store(int $days, int $loweredAt): void {
		$this->state->set(self::STATE, json_encode(['days' => $days, 'loweredAt' => $loweredAt], JSON_THROW_ON_ERROR));
	}
}
