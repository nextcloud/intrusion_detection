<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Learning;

/**
 * A learning period would last more than {@see LearningService::MAX_DAYS}
 * from its start. Starting it again or extending it while it runs never
 * moves its start, so protection cannot be kept off indefinitely.
 */
class LearningLimitException extends \InvalidArgumentException {
	/**
	 * @param int $latest the latest end the running period may have
	 * @param int $startedAt when the running period started, 0 for a new one
	 */
	public function __construct(
		public readonly int $latest,
		public readonly int $startedAt,
	) {
		parent::__construct(sprintf(
			'Learning mode lasts at most %d days in all. This learning period started on %s, so it can last until %s at the latest.',
			LearningService::MAX_DAYS,
			gmdate('Y-m-d H:i', $startedAt) . ' UTC',
			gmdate('Y-m-d H:i', $latest) . ' UTC',
		));
	}
}
