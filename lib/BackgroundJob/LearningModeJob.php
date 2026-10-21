<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Notification\LearningNotices;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\TimedJob;

/**
 * Hourly: a day before the learning period ends, tells the administrators
 * what would have happened; when it is over, ends learning mode and tells
 * them that protection started.
 */
class LearningModeJob extends TimedJob {
	public function __construct(
		ITimeFactory $time,
		private readonly LearningService $learning,
		private readonly LearningNotices $notices,
	) {
		parent::__construct($time);
		$this->setInterval(3600);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		if ($this->learning->expireIfDue()) {
			$this->notices->protectionStarted();
			return;
		}
		$this->notices->sendEndingNoticeIfDue();
	}
}
