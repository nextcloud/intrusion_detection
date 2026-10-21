<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\TimedJob;

/**
 * Hourly: end the requests for approval whose time ran out and tell the ones
 * who asked; remove decided requests after 90 days. A request is also checked
 * for expiry whenever someone tries to decide it, so the hour between two
 * runs never lets an expired request be approved.
 */
class ApprovalExpiryJob extends TimedJob {
	public function __construct(
		ITimeFactory $time,
		private readonly ApprovalService $approvals,
	) {
		parent::__construct($time);
		$this->setInterval(3600);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		$this->approvals->expireDue();
	}
}
