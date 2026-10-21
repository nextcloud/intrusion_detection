<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Blocklist\BlocklistContribution;
use OCA\IntrusionDetection\Blocklist\ContributionSettings;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJob;
use OCP\BackgroundJob\TimedJob;

/**
 * Once a day: sends the reports for the shared blocklist, only when the
 * feature is available in config.php and the admin switched it on.
 */
class ContributionJob extends TimedJob {
	public function __construct(
		ITimeFactory $time,
		private readonly ContributionSettings $config,
		private readonly BlocklistContribution $contribution,
	) {
		parent::__construct($time);
		$this->setInterval(86400);
		$this->setTimeSensitivity(IJob::TIME_INSENSITIVE);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		if (!$this->config->isEnabled()) {
			return;
		}
		$this->contribution->send();
	}
}
