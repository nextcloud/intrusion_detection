<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\AdminChange\AdminGrantGate;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCP\IL10N;
use OCP\SetupCheck\ISetupCheck;
use OCP\SetupCheck\SetupResult;

/**
 * Setup check 11: with four-eyes approval on, a new administrator needs a
 * second administrator to approve. With fewer than two, nobody could.
 */
class ApprovalCheck implements ISetupCheck {
	public function __construct(
		private readonly AdminGrantGate $gate,
		private readonly Approvers $approvers,
		private readonly IL10N $l,
	) {
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Approval of new administrators');
	}

	#[\Override]
	public function getCategory(): string {
		return 'security';
	}

	#[\Override]
	public function run(): SetupResult {
		if (!$this->gate->isRequired()) {
			return SetupResult::success($this->l->t('New administrators do not need the approval of a second administrator.'));
		}
		$count = $this->approvers->count();
		if ($count < 2) {
			return SetupResult::error($this->l->n(
				'A second administrator must approve every new administrator, but only %n administrator exists, so nobody can approve. Add the next administrator with "occ group:adduser admin <account>", which needs no approval.',
				'A second administrator must approve every new administrator, but only %n administrators exist, so nobody can approve. Add the next administrator with "occ group:adduser admin <account>", which needs no approval.',
				$count,
			));
		}
		return SetupResult::success($this->l->n(
			'New administrators need the approval of a second administrator; %n administrators can approve.',
			'New administrators need the approval of a second administrator; %n administrators can approve.',
			$count,
		));
	}
}
