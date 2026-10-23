<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Privacy\UserDataCleanup;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJobList;
use OCP\BackgroundJob\QueuedJob;
use OCP\IUserManager;
use Psr\Log\LoggerInterface;

/**
 * Queued when the data of a deleted account could not be removed at its
 * deletion: removes it ({@see UserDataCleanup::deleteUser()}), and queues
 * itself again after a failure, MAX_ATTEMPTS times in all.
 *
 * The argument is the account and the number of the attempt. An account
 * created again with the same name in the meantime is left alone.
 */
class UserDataCleanupJob extends QueuedJob {
	public const MAX_ATTEMPTS = 5;

	public function __construct(
		ITimeFactory $time,
		private readonly UserDataCleanup $cleanup,
		private readonly IUserManager $userManager,
		private readonly IJobList $jobList,
		private readonly LoggerInterface $logger,
	) {
		parent::__construct($time);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		if (!is_array($argument) || !is_string($argument['uid'] ?? null) || !is_int($argument['attempt'] ?? null)) {
			return;
		}
		$uid = $argument['uid'];
		if ($this->userManager->userExists($uid)) {
			return;
		}
		try {
			$this->cleanup->deleteUser($uid);
		} catch (\Throwable $e) {
			if ($argument['attempt'] >= self::MAX_ATTEMPTS) {
				$this->logger->error('Intrusion detection gave up removing the data of a deleted account after {attempts} attempts', ['attempts' => self::MAX_ATTEMPTS, 'exception' => $e]);
				return;
			}
			$this->logger->warning('Intrusion detection could not remove the data of a deleted account; it tries again', ['exception' => $e]);
			$this->jobList->add(self::class, ['uid' => $uid, 'attempt' => $argument['attempt'] + 1]);
		}
	}
}
