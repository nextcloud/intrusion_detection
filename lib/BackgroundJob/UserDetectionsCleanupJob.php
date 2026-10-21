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

/**
 * Queued at an account's deletion: rewrites the detections that name the
 * account without it ({@see UserDataCleanup::scrubDetections()}). One run
 * rewrites at most UserDataCleanup::BATCH × BATCHES_PER_RUN detections and
 * queues the rest for the next run, so that an account named in many
 * detections neither slows its deletion nor holds up the other jobs.
 *
 * The argument is the account, the last detection id at its deletion (a new
 * account with the same name is not touched) and where the last run ended.
 */
class UserDetectionsCleanupJob extends QueuedJob {
	public const BATCHES_PER_RUN = 50;

	public function __construct(
		ITimeFactory $time,
		private readonly UserDataCleanup $cleanup,
		private readonly IJobList $jobList,
	) {
		parent::__construct($time);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		if (!is_array($argument) || !is_string($argument['uid'] ?? null) || !is_int($argument['upTo'] ?? null)) {
			return;
		}
		$after = is_int($argument['after'] ?? null) ? $argument['after'] : 0;
		$last = $this->cleanup->scrubDetections($argument['uid'], $argument['upTo'], $after, self::BATCHES_PER_RUN);
		if ($last !== null) {
			$this->jobList->add(self::class, ['uid' => $argument['uid'], 'upTo' => $argument['upTo'], 'after' => $last]);
		}
	}
}
