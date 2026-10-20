<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Learning\LearningService;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\TimedJob;

/**
 * Hourly: ends learning mode when its period is over.
 */
class LearningModeJob extends TimedJob {
	public function __construct(
		ITimeFactory $time,
		private readonly LearningService $learning,
	) {
		parent::__construct($time);
		$this->setInterval(3600);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		$this->learning->expireIfDue();
	}
}
