<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\StaleCredential\StaleCredentialSweep;
use OCA\IntrusionDetection\Traps\TrapNameCollisions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\TimedJob;
use Psr\Log\LoggerInterface;

/**
 * Hourly: count the accounts that cannot confirm a login, and look the
 * reserved names and decoy login names up as accounts. The admin page, the
 * status endpoint, the dashboard widget and the setup checks read the stored
 * results, so none of them counts or looks up anything itself. Once a day,
 * also look at the app passwords and devices nobody used for 90 days.
 */
class StatusRefreshJob extends TimedJob {
	public function __construct(
		ITimeFactory $time,
		private readonly ConfirmationCoverage $coverage,
		private readonly TrapNameCollisions $collisions,
		private readonly StaleCredentialSweep $staleCredentials,
		private readonly LoggerInterface $logger,
	) {
		parent::__construct($time);
		$this->setInterval(3600);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		$steps = [
			'coverage' => fn () => $this->coverage->recount(),
			'trap_names' => fn () => $this->collisions->refresh(),
			'stale_credentials' => fn () => $this->staleCredentials->runIfDue(),
		];
		foreach ($steps as $name => $step) {
			try {
				$step();
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not refresh {step}', ['step' => $name, 'exception' => $e]);
			}
		}
	}
}
