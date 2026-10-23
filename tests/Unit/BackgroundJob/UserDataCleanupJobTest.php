<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\BackgroundJob;

use OCA\IntrusionDetection\BackgroundJob\UserDataCleanupJob;
use OCA\IntrusionDetection\Listener\UserDeletedListener;
use OCA\IntrusionDetection\Privacy\UserDataCleanup;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJobList;
use OCP\IUser;
use OCP\IUserManager;
use OCP\User\Events\UserDeletedEvent;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class UserDataCleanupJobTest extends TestCase {
	public function testARemovalThatFailsAtTheDeletionIsQueued(): void {
		$cleanup = $this->createMock(UserDataCleanup::class);
		$cleanup->method('deleteUser')->willThrowException(new \RuntimeException('database gone'));
		$jobs = $this->createMock(IJobList::class);
		$jobs->expects($this->once())->method('add')->with(UserDataCleanupJob::class, ['uid' => 'alice', 'attempt' => 1]);
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		(new UserDeletedListener($cleanup, $jobs, $this->createMock(LoggerInterface::class)))->handle(new UserDeletedEvent($user));
	}

	public function testAFailedAttemptIsTriedAgain(): void {
		$cleanup = $this->createMock(UserDataCleanup::class);
		$cleanup->expects($this->once())->method('deleteUser')->with('alice')->willThrowException(new \RuntimeException('database gone'));
		$jobs = $this->createMock(IJobList::class);
		$jobs->expects($this->once())->method('add')->with(UserDataCleanupJob::class, ['uid' => 'alice', 'attempt' => 3]);
		$this->runJob($cleanup, $jobs, ['uid' => 'alice', 'attempt' => 2]);
	}

	public function testItGivesUpAfterTheLastAttempt(): void {
		$cleanup = $this->createMock(UserDataCleanup::class);
		$cleanup->method('deleteUser')->willThrowException(new \RuntimeException('database gone'));
		$jobs = $this->createMock(IJobList::class);
		$jobs->expects($this->never())->method('add');
		$this->runJob($cleanup, $jobs, ['uid' => 'alice', 'attempt' => UserDataCleanupJob::MAX_ATTEMPTS]);
	}

	public function testASuccessQueuesNothing(): void {
		$cleanup = $this->createMock(UserDataCleanup::class);
		$cleanup->expects($this->once())->method('deleteUser')->with('alice');
		$jobs = $this->createMock(IJobList::class);
		$jobs->expects($this->never())->method('add');
		$this->runJob($cleanup, $jobs, ['uid' => 'alice', 'attempt' => 1]);
	}

	public function testAnAccountCreatedAgainIsLeftAlone(): void {
		$cleanup = $this->createMock(UserDataCleanup::class);
		$cleanup->expects($this->never())->method('deleteUser');
		$this->runJob($cleanup, $this->createMock(IJobList::class), ['uid' => 'alice', 'attempt' => 1], exists: true);
	}

	/**
	 * @param array<string, mixed> $argument
	 */
	private function runJob(UserDataCleanup $cleanup, IJobList $jobs, array $argument, bool $exists = false): void {
		$users = $this->createMock(IUserManager::class);
		$users->method('userExists')->willReturn($exists);
		$job = new UserDataCleanupJob($this->createMock(ITimeFactory::class), $cleanup, $users, $jobs, $this->createMock(LoggerInterface::class));
		self::invokePrivate($job, 'run', [$argument]);
	}
}
