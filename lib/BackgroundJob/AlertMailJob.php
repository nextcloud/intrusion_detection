<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\MailQueue;
use OCA\IntrusionDetection\Notification\ShareOwnerAlerts;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\QueuedJob;

/**
 * Sends one email about a detection, queued by {@see MailQueue}. The email
 * is built from the detection as it is stored when the job runs; a
 * detection or account that is gone by then gets no email.
 */
class AlertMailJob extends QueuedJob {
	public function __construct(
		ITimeFactory $time,
		private readonly DetectionMapper $detections,
		private readonly UserAlerts $userAlerts,
		private readonly AdminAlerts $adminAlerts,
		private readonly ShareOwnerAlerts $shareOwnerAlerts,
	) {
		parent::__construct($time);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		if (!is_array($argument) || !is_int($argument['detection'] ?? null)) {
			return;
		}
		try {
			$detection = $this->detections->findById($argument['detection']);
		} catch (DoesNotExistException) {
			return;
		}
		$uid = $argument['uid'] ?? null;
		match ($argument['kind'] ?? null) {
			MailQueue::KIND_USER => is_string($uid) ? $this->userAlerts->sendMail($detection, $uid) : null,
			MailQueue::KIND_ADMIN => $this->adminAlerts->sendMail($detection),
			MailQueue::KIND_SHARE_OWNER => $this->shareOwnerAlerts->sendMail($detection),
			default => null,
		};
	}
}
