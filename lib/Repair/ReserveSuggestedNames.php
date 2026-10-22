<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Repair;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Traps\ReservedNames;
use OCP\Migration\IOutput;
use OCP\Migration\IRepairStep;
use Psr\Log\LoggerInterface;

/**
 * Reserves the suggested login names, such as "administrator" or "root",
 * when the app is installed, leaving out every name that is an account in
 * any user backend. Runs once, before {@see StartLearningMode} records the
 * installation; installs from before this step keep their names as they are.
 */
class ReserveSuggestedNames implements IRepairStep {
	public function __construct(
		private readonly Settings $settings,
		private readonly ReservedNames $names,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function getName(): string {
		return 'Reserve the usual admin login names that no account uses';
	}

	#[\Override]
	public function run(IOutput $output): void {
		if ($this->settings->getInt(GlobalSettings::INSTALLED_AT) !== 0) {
			return;
		}
		try {
			$reserved = $this->names->reserveSuggestions();
		} catch (\Throwable $e) {
			// A user backend that cannot be asked, such as an unreachable LDAP server, must not stop the installation.
			$this->logger->warning('Intrusion detection could not reserve the suggested login names', ['exception' => $e]);
			$output->warning('No login names were reserved; reserve them on the Blocks tab.');
			return;
		}
		if ($reserved !== []) {
			$output->info('Reserved login names: ' . implode(', ', $reserved));
		}
	}
}
