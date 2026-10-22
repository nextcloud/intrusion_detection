<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\BackgroundJob;

use OCA\IntrusionDetection\BackgroundJob\Cleanup;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\LoginHistory\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Notification\Db\AlertMapper;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\Response\Db\FlagMapper;
use OCA\IntrusionDetection\Response\Db\ProtectedAccountMapper;
use OCA\IntrusionDetection\State\AppState;
use OCA\IntrusionDetection\State\HotState;
use OCA\IntrusionDetection\Takeover\Db\LockLinkMapper;
use OCA\IntrusionDetection\Takeover\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCA\IntrusionDetection\TrustedNetwork\Db\TrustedNetworkMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class CleanupTest extends TestCase {
	private const NOW = 1_800_000_000;

	public function testAFailingStepIsLoggedAndTheOthersStillRun(): void {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(self::NOW);
		$attempts = $this->createMock(AttemptMapper::class);
		$attempts->expects($this->once())->method('deleteOlderThan')->with(self::NOW - AttemptRecorder::RETENTION)->willThrowException(new \RuntimeException('deadlock'));
		$attempts->expects($this->once())->method('hasMoreThan')->with(AttemptRecorder::FLOOD_ROWS)->willReturn(false);
		$flags = $this->createMock(FlagMapper::class);
		$flags->expects($this->once())->method('deleteExpired')->with(self::NOW);
		$changes = $this->createMock(SecurityChangeMapper::class);
		$changes->expects($this->once())->method('forgetAddressesBefore')->with(
			self::NOW - SecurityChangeLog::ADDRESS_TTL,
			self::NOW - SecurityChangeLog::ADDRESS_TTL - Cleanup::ADDRESS_LOOK_BACK,
		);
		$stats = $this->createMock(FailedLoginStats::class);
		$stats->expects($this->once())->method('deleteExpired');
		$settings = $this->createMock(AppSettings::class);
		$settings->method('retentionDays')->willReturn(30);
		$settings->method('banHistoryDays')->willReturn(30);
		$logger = $this->createMock(LoggerInterface::class);
		$failed = [];
		$logger->method('error')->willReturnCallback(static function (string $message, array $context) use (&$failed): void {
			$failed[] = $context['step'] . ': ' . $context['exception']->getMessage();
		});

		$job = new Cleanup(
			$time, $attempts, $this->createMock(LoginMapper::class), $this->createMock(BanMapper::class), $flags, $settings,
			$this->createMock(ProtectedAccountMapper::class), $this->createMock(AlertMapper::class), $this->createMock(\OCA\IntrusionDetection\Response\ResetMailSuppressor::class),
			$this->createMock(TokenOriginMapper::class), $this->createMock(TrustedNetworkMapper::class), $this->createMock(StepUpSessionMapper::class),
			$this->createMock(DetectionTotals::class), $this->createMock(KnownDevices::class), $this->createMock(LoginHistoryMapper::class),
			$changes, $this->createMock(LockLinkMapper::class), $stats,
			$this->createMock(\OCA\IntrusionDetection\Confirm\AbandonedLogins::class), $this->createMock(\OCA\IntrusionDetection\Response\FlaggedSources::class), $logger,
			$this->createMock(AppState::class), $this->createMock(HotState::class),
		);
		self::invokePrivate($job, 'run', [null]);
		$this->assertSame(['attempts: deadlock'], $failed);
	}

	public function testRecordingAnAttemptNeverDeletesOldOnes(): void {
		$mapper = $this->createMock(AttemptMapper::class);
		$mapper->expects($this->exactly(60))->method('insert');
		$mapper->expects($this->never())->method('deleteOlderThan');
		$fingerprinter = $this->createMock(\OCA\IntrusionDetection\Crypto\Fingerprinter::class);
		$fingerprinter->method('name')->willReturn('n');
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(self::NOW);
		$recorder = new AttemptRecorder($mapper, $fingerprinter, $time, $this->createMock(HotState::class));
		for ($i = 0; $i < 60; $i++) {
			$recorder->record(\OCA\IntrusionDetection\Db\AttemptKind::PasswordReset, \OCA\IntrusionDetection\Net\SourceKey::fromIp('203.0.113.7'), 'alice');
		}
	}
}
