<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\BackgroundJob;

use OCA\IntrusionDetection\BackgroundJob\UserDetectionsCleanupJob;
use OCA\IntrusionDetection\Privacy\UserDataCleanup;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJobList;
use Test\TestCase;

class UserDetectionsCleanupJobTest extends TestCase {
	public function testARunThatDoesNotFinishQueuesTheRest(): void {
		$cleanup = $this->createMock(UserDataCleanup::class);
		$cleanup->expects($this->once())->method('scrubDetections')->with('alice', '900', '0', UserDetectionsCleanupJob::BATCHES_PER_RUN)->willReturn('400');
		$jobs = $this->createMock(IJobList::class);
		$jobs->expects($this->once())->method('add')->with(UserDetectionsCleanupJob::class, ['uid' => 'alice', 'upTo' => '900', 'after' => '400']);
		self::invokePrivate(new UserDetectionsCleanupJob($this->createMock(ITimeFactory::class), $cleanup, $jobs), 'run', [['uid' => 'alice', 'upTo' => '900']]);
	}

	public function testAFinishedRunQueuesNothing(): void {
		$cleanup = $this->createMock(UserDataCleanup::class);
		$cleanup->expects($this->once())->method('scrubDetections')->with('alice', '900', '400')->willReturn(null);
		$jobs = $this->createMock(IJobList::class);
		$jobs->expects($this->never())->method('add');
		self::invokePrivate(new UserDetectionsCleanupJob($this->createMock(ITimeFactory::class), $cleanup, $jobs), 'run', [['uid' => 'alice', 'upTo' => '900', 'after' => '400']]);
	}

	public function testABrokenArgumentDoesNothing(): void {
		$cleanup = $this->createMock(UserDataCleanup::class);
		$cleanup->expects($this->never())->method('scrubDetections');
		self::invokePrivate(new UserDetectionsCleanupJob($this->createMock(ITimeFactory::class), $cleanup, $this->createMock(IJobList::class)), 'run', [['uid' => 'alice']]);
	}
}
