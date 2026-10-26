<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\BackgroundJob;

use OCA\IntrusionDetection\BackgroundJob\Cleanup;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\IPurges;
use OCA\IntrusionDetection\Detection\AttemptCounters;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\State\HotState;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Utility\ITimeFactory;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class CleanupTest extends TestCase {
	private const NOW = 1_800_000_000;

	public function testAFailingOwnerIsLoggedAndTheOthersStillRun(): void {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(self::NOW);
		$ran = [];
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(function (string $class) use (&$ran): IPurges {
			$purger = $this->createMock(IPurges::class);
			$purger->expects($this->once())->method('purge')->with(self::NOW)->willReturnCallback(static function () use ($class, &$ran): int {
				$ran[] = $class;
				if ($class === AttemptRecorder::class) {
					throw new \RuntimeException('deadlock');
				}
				return 0;
			});
			return $purger;
		});
		$logger = $this->createMock(LoggerInterface::class);
		$failed = [];
		$logger->method('error')->willReturnCallback(static function (string $message, array $context) use (&$failed): void {
			$failed[] = $context['step'] . ': ' . $context['exception']->getMessage();
		});

		self::invokePrivate(new Cleanup($time, $container, $logger), 'run', [null]);
		$this->assertSame(array_keys(Cleanup::PURGES), $ran);
		$this->assertSame([AttemptRecorder::class . ': deadlock'], $failed);
	}

	public function testTheFloodStateIsUpdatedEvenWhenTheAttemptsCannotBeDeleted(): void {
		$mapper = $this->createMock(AttemptMapper::class);
		$mapper->expects($this->once())->method('deleteOlderThan')->with(self::NOW - AttemptRecorder::RETENTION)->willThrowException(new \RuntimeException('deadlock'));
		$mapper->expects($this->once())->method('hasMoreThan')->with(AttemptRecorder::FLOOD_ROWS)->willReturn(true);
		$hotState = $this->createMock(HotState::class);
		$hotState->expects($this->once())->method('setAttemptsFloodUntil')->with(self::NOW + 600);
		$recorder = new AttemptRecorder($mapper, $this->createMock(\OCA\IntrusionDetection\Crypto\Fingerprinter::class), $this->createMock(ITimeFactory::class), $hotState, new AttemptCounters(FixedCaches::none()));
		$this->expectExceptionMessage('deadlock');
		$recorder->purge(self::NOW);
	}

	public function testRecordingAnAttemptNeverDeletesOldOnes(): void {
		$mapper = $this->createMock(AttemptMapper::class);
		$mapper->expects($this->exactly(60))->method('insert');
		$mapper->expects($this->never())->method('deleteOlderThan');
		$fingerprinter = $this->createMock(\OCA\IntrusionDetection\Crypto\Fingerprinter::class);
		$fingerprinter->method('name')->willReturn('n');
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(self::NOW);
		$recorder = new AttemptRecorder($mapper, $fingerprinter, $time, $this->createMock(HotState::class), new AttemptCounters(FixedCaches::none()));
		for ($i = 0; $i < 60; $i++) {
			$recorder->record(\OCA\IntrusionDetection\Db\AttemptKind::PasswordReset, \OCA\IntrusionDetection\Net\SourceKey::fromIp('203.0.113.7'), 'alice');
		}
	}
}
