<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Repair;

use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\State\AppState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Migration\IOutput;
use OCP\Migration\IRepairStep;

/**
 * Starts the learning period when the app is installed: for seven days every
 * check observes instead of acting, so the admin can see what it would do.
 * Runs once; re-enabling the app does not start it again.
 */
class StartLearningMode implements IRepairStep {
	public function __construct(
		private readonly LearningService $learning,
		private readonly ITimeFactory $timeFactory,
		private readonly AppState $state,
	) {
	}

	#[\Override]
	public function getName(): string {
		return 'Start the intrusion detection learning period';
	}

	#[\Override]
	public function run(IOutput $output): void {
		if ($this->state->getInt(AppState::INSTALLED_AT) !== 0) {
			return;
		}
		$now = $this->timeFactory->getTime();
		$this->state->setInt(AppState::INSTALLED_AT, $now);
		$this->learning->startAtInstall($now);
	}
}
