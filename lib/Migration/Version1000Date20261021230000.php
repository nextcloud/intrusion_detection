<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Migration;

use Closure;
use OCA\IntrusionDetection\Check\Checks\AdminChange;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce;
use OCA\IntrusionDetection\Detection\DetectionAccounts;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

/**
 * Records the accounts that detections stored before name under the fact
 * keys requested_by, approved_by (admin changes), owner and managers
 * (share link attacks), so that deleting such an account finds them. In
 * batches by id; nothing is recorded twice.
 */
class Version1000Date20261021230000 extends SimpleMigrationStep {
	/** The checks whose detections use those keys */
	public const CHECKS = [AdminChange::ID, ShareBruteforce::ID];

	public function __construct(
		private readonly DetectionAccounts $accounts,
	) {
	}

	/**
	 * @param Closure(): \OCP\DB\ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function postSchemaChange(IOutput $output, Closure $schemaClosure, array $options): void {
		$this->accounts->backfill(self::CHECKS);
	}
}
