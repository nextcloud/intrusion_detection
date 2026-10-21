<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Lockdown\LockdownService;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJob;
use OCP\BackgroundJob\TimedJob;

/**
 * Ends a lockdown whose time is up and tells the administrators. The
 * effects stop at the planned time anyway: they compare it with the clock.
 * Nothing but one app config read while no lockdown runs.
 */
class LockdownJob extends TimedJob {
	public function __construct(
		ITimeFactory $time,
		private readonly LockdownService $lockdown,
	) {
		parent::__construct($time);
		$this->setInterval(60);
		$this->setTimeSensitivity(IJob::TIME_SENSITIVE);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		$this->lockdown->expireIfDue();
	}
}
