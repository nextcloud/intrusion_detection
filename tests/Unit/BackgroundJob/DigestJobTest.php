<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\BackgroundJob;

use OCA\IntrusionDetection\BackgroundJob\DigestJob;
use OCA\IntrusionDetection\Notification\DigestSender;
use OCP\AppFramework\Utility\ITimeFactory;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class DigestJobTest extends TestCase {
	public function testItRunsHourlyAndSendsWhenDue(): void {
		$sender = $this->createMock(DigestSender::class);
		$sender->expects($this->once())->method('sendIfDue')->willReturn(DigestSender::RESULT_NOT_DUE);
		$job = new DigestJob($this->createMock(ITimeFactory::class), $sender, $this->createMock(LoggerInterface::class));
		$this->assertSame(3600, $job->getInterval());
		$run = new \ReflectionMethod($job, 'run');
		$run->invoke($job, null);
	}
}
