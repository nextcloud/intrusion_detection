<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Export\FirewallExporter;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJob;
use OCP\BackgroundJob\TimedJob;

/**
 * Every five minutes: rewrites the firewall export when a block ended since
 * the last write, so ended blocks leave the files. Does nothing otherwise.
 */
class FirewallExportJob extends TimedJob {
	public function __construct(
		ITimeFactory $time,
		private readonly FirewallExporter $exporter,
	) {
		parent::__construct($time);
		$this->setInterval(300);
		$this->setTimeSensitivity(IJob::TIME_SENSITIVE);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		$this->exporter->writeIfDue();
	}
}
