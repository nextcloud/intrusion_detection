<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Repair;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
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
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	#[\Override]
	public function getName(): string {
		return 'Start the intrusion detection learning period';
	}

	#[\Override]
	public function run(IOutput $output): void {
		if ($this->settings->getInt(GlobalSettings::INSTALLED_AT) !== 0) {
			return;
		}
		$now = $this->timeFactory->getTime();
		$this->settings->setGlobal(GlobalSettings::INSTALLED_AT, $now);
		$this->settings->setGlobal(GlobalSettings::LEARNING_UNTIL, $now + GlobalSettings::LEARNING_DEFAULT_PERIOD);
	}
}
