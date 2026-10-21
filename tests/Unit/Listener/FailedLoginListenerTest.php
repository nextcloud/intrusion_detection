<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Listener;

use OCA\IntrusionDetection\Check\Checks\AccountUnderAttackDetector;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffingDetector;
use OCA\IntrusionDetection\Check\Checks\DecoyCredentialDetector;
use OCA\IntrusionDetection\Check\Checks\PasswordSprayingDetector;
use OCA\IntrusionDetection\Check\Checks\ReservedNameDetector;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Listener\FailedLoginListener;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCP\Authentication\Events\AnyLoginFailedEvent;
use OCP\IRequest;
use OCP\IUserManager;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class FailedLoginListenerTest extends TestCase {
	/**
	 * @return array<string, array{?string, AttemptKind}>
	 */
	public static function passwords(): array {
		return [
			'settings app password' => ['AbCdE-fGhJk-LmNpQ-rStWx-Yz234', AttemptKind::AppPassword],
			'login flow token' => [str_repeat('aB3', 24), AttemptKind::AppPassword],
			'ordinary password' => ['Summer2026!', AttemptKind::PasswordLogin],
			'71 characters' => [str_repeat('a', 71), AttemptKind::PasswordLogin],
			'groups of the wrong length' => ['AbCdE-fGhJk-LmNpQ-rStWx', AttemptKind::PasswordLogin],
			'no password' => [null, AttemptKind::PasswordLogin],
		];
	}

	#[DataProvider('passwords')]
	public function testTheKindIsGuessedFromTheShape(?string $password, AttemptKind $kind): void {
		$this->assertSame($kind, FailedLoginListener::kindOf($password));
	}

	public function testAFailingDetectorIsLoggedAndTheOthersStillRun(): void {
		$settings = $this->createMock(Settings::class);
		$settings->method('isEnabled')->willReturn(true);
		$settings->method('modeState')->willReturn(new ModeState(Mode::Protect, Mode::Protect));
		$addresses = $this->createMock(RemoteAddressResolver::class);
		$addresses->method('current')->willReturn(SourceKey::fromIp('198.51.100.7'));
		$source = SourceKey::fromIp('198.51.100.7');
		$recorder = $this->createMock(AttemptRecorder::class);
		$recorder->method('record')->willReturn(new AttemptRecord(AttemptKind::PasswordLogin, $source, 'aa', null, null, 'bb', ['bb'], time(), true));
		$spraying = $this->createMock(PasswordSprayingDetector::class);
		$spraying->method('detect')->willThrowException(new \RuntimeException('database gone'));
		$stuffing = $this->createMock(CredentialStuffingDetector::class);
		$stuffing->expects($this->once())->method('detect');
		$accountUnderAttack = $this->createMock(AccountUnderAttackDetector::class);
		$accountUnderAttack->expects($this->once())->method('detect');
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error')->with($this->anything(), $this->callback(
			static fn (array $context): bool => $context['step'] === 'password_spraying',
		));

		$listener = new FailedLoginListener(
			$settings, $addresses, $recorder, $this->createMock(DecoyCredentialDetector::class), $this->createMock(ReservedNameDetector::class),
			$stuffing, $spraying, $accountUnderAttack, $this->createMock(RiskScorer::class),
			$this->createMock(IUserManager::class), $this->createMock(IRequest::class), $logger,
			$this->createMock(FailedLoginStats::class),
			$this->createMock(\OCA\IntrusionDetection\Login\EmailAccounts::class),
		);
		$listener->handle(new AnyLoginFailedEvent('alice', 'secret'));
	}

	public function testABypassListedSourceIsIgnoredEntirely(): void {
		$settings = $this->createMock(Settings::class);
		$settings->method('isEnabled')->willReturn(true);
		$addresses = $this->createMock(RemoteAddressResolver::class);
		$addresses->method('current')->willReturn(SourceKey::fromIp('198.51.100.7'));
		$addresses->method('isBypassListed')->willReturn(true);
		$recorder = $this->createMock(AttemptRecorder::class);
		$recorder->expects($this->never())->method('record');
		$decoys = $this->createMock(DecoyCredentialDetector::class);
		$decoys->expects($this->never())->method('detect');
		$reserved = $this->createMock(ReservedNameDetector::class);
		$reserved->expects($this->never())->method('detect');

		$listener = new FailedLoginListener(
			$settings, $addresses, $recorder, $decoys, $reserved,
			$this->createMock(CredentialStuffingDetector::class), $this->createMock(PasswordSprayingDetector::class), $this->createMock(AccountUnderAttackDetector::class),
			$this->createMock(RiskScorer::class),
			$this->createMock(IUserManager::class), $this->createMock(IRequest::class), $this->createMock(LoggerInterface::class),
			$this->createMock(FailedLoginStats::class),
			$this->createMock(\OCA\IntrusionDetection\Login\EmailAccounts::class),
		);
		$listener->handle(new AnyLoginFailedEvent('admin', 'secret'));
	}

	public function testWithoutAMemoryCacheAnEmailIsOnlyLookedUpForTheChecksThatCountPerAccount(): void {
		$settings = $this->createMock(Settings::class);
		$settings->method('isEnabled')->willReturn(true);
		$settings->method('modeState')->willReturnCallback(static fn (string $id): ModeState => $id === \OCA\IntrusionDetection\Check\Checks\AccountUnderAttack::ID
			? new ModeState(Mode::Off, Mode::Off)
			: new ModeState(Mode::Protect, Mode::Protect));
		$addresses = $this->createMock(RemoteAddressResolver::class);
		$addresses->method('current')->willReturn(SourceKey::fromIp('198.51.100.7'));
		$recorder = $this->createMock(AttemptRecorder::class);
		$recorder->expects($this->once())->method('record')->with(AttemptKind::PasswordLogin, $this->anything(), 'alice@example.com', null)
			->willReturn(new AttemptRecord(AttemptKind::PasswordLogin, SourceKey::fromIp('198.51.100.7'), 'aa', null, null, 'bb', ['bb'], time(), true));
		$users = $this->createMock(IUserManager::class);
		$users->method('getUserNameFromLoginName')->willReturnArgument(0);
		$users->expects($this->never())->method('getByEmail');
		$emails = new \OCA\IntrusionDetection\Login\EmailAccounts($users, $this->createMock(\OCP\ICacheFactory::class));

		$listener = new FailedLoginListener(
			$settings, $addresses, $recorder, $this->createMock(DecoyCredentialDetector::class), $this->createMock(ReservedNameDetector::class),
			$this->createMock(CredentialStuffingDetector::class), $this->createMock(PasswordSprayingDetector::class), $this->createMock(AccountUnderAttackDetector::class),
			$this->createMock(RiskScorer::class), $users, $this->createMock(IRequest::class), $this->createMock(LoggerInterface::class),
			$this->createMock(FailedLoginStats::class), $emails,
		);
		$listener->handle(new AnyLoginFailedEvent('alice@example.com', 'secret'));
	}
}
