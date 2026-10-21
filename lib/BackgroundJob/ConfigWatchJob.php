<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\AdminChange\ConfigWatch;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\TimedJob;

/**
 * Every 5 minutes: compare the watched security settings with the last
 * snapshot and report each change. One read of the settings, writes only on
 * a change.
 */
class ConfigWatchJob extends TimedJob {
	public function __construct(
		ITimeFactory $time,
		private readonly ConfigWatch $watch,
	) {
		parent::__construct($time);
		$this->setInterval(300);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		$this->watch->run();
	}
}
