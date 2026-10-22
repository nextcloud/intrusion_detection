<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\BackgroundJob;

use OCA\IntrusionDetection\BackgroundJob\AlertMailJob;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\MailQueue;
use OCA\IntrusionDetection\Notification\ShareOwnerAlerts;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Utility\ITimeFactory;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class AlertMailJobTest extends TestCase {
	private DetectionMapper&MockObject $detections;
	private UserAlerts&MockObject $users;
	private AdminAlerts&MockObject $admins;
	private ShareOwnerAlerts&MockObject $shareOwners;
	private Detection $detection;

	protected function setUp(): void {
		parent::setUp();
		$this->detection = new Detection();
		$this->detections = $this->createMock(DetectionMapper::class);
		$this->detections->method('findById')->willReturnCallback(fn (int $id): Detection => $id === 7 ? $this->detection : throw new DoesNotExistException('gone'));
		$this->users = $this->createMock(UserAlerts::class);
		$this->admins = $this->createMock(AdminAlerts::class);
		$this->shareOwners = $this->createMock(ShareOwnerAlerts::class);
	}

	public function testEachKindGoesToItsSender(): void {
		$this->users->expects($this->once())->method('sendMail')->with($this->detection, 'alice');
		$this->admins->expects($this->once())->method('sendMail')->with($this->detection);
		$this->shareOwners->expects($this->once())->method('sendMail')->with($this->detection);
		$this->runJob(['kind' => MailQueue::KIND_USER, 'detection' => 7, 'uid' => 'alice']);
		$this->runJob(['kind' => MailQueue::KIND_ADMIN, 'detection' => 7]);
		$this->runJob(['kind' => MailQueue::KIND_SHARE_OWNER, 'detection' => 7]);
	}

	public function testABrokenArgumentOrADeletedDetectionSendsNothing(): void {
		$this->users->expects($this->never())->method('sendMail');
		$this->admins->expects($this->never())->method('sendMail');
		$this->shareOwners->expects($this->never())->method('sendMail');
		$this->runJob(null);
		$this->runJob(['kind' => MailQueue::KIND_USER, 'detection' => 7]);
		$this->runJob(['kind' => MailQueue::KIND_USER, 'detection' => '7', 'uid' => 'alice']);
		$this->runJob(['kind' => 'other', 'detection' => 7]);
		$this->runJob(['kind' => MailQueue::KIND_ADMIN, 'detection' => 8]);
	}

	private function runJob(mixed $argument): void {
		$job = new AlertMailJob($this->createMock(ITimeFactory::class), $this->detections, $this->users, $this->admins, $this->shareOwners);
		self::invokePrivate($job, 'run', [$argument]);
	}
}
