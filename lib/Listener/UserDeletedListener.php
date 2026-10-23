<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\BackgroundJob\UserDataCleanupJob;
use OCA\IntrusionDetection\Privacy\UserDataCleanup;
use OCP\BackgroundJob\IJobList;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\User\Events\UserDeletedEvent;
use Psr\Log\LoggerInterface;

/**
 * Removes a deleted account from the app's data; see {@see UserDataCleanup}.
 * When that fails, a queued job tries again ({@see UserDataCleanupJob}).
 *
 * @template-implements IEventListener<UserDeletedEvent>
 */
class UserDeletedListener implements IEventListener {
	public function __construct(
		private readonly UserDataCleanup $cleanup,
		private readonly IJobList $jobList,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof UserDeletedEvent) {
			return;
		}
		$uid = $event->getUser()->getUID();
		try {
			$this->cleanup->deleteUser($uid);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not remove the data of a deleted account; a background job tries again', ['exception' => $e]);
			$this->jobList->add(UserDataCleanupJob::class, ['uid' => $uid, 'attempt' => 1]);
		}
	}
}
