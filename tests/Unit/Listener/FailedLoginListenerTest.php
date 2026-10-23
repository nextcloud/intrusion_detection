<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Listener;

use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack\AccountUnderAttackDetector;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Listener\FailedLoginListener;
use OCA\IntrusionDetection\Login\EmailAccounts;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\Signal\Dispatch;
use OCA\IntrusionDetection\Signal\FailedLogin;
use OCA\IntrusionDetection\Signal\FailedLoginAttempt;
use OCA\IntrusionDetection\Signal\SignalDispatcher;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
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

	public function testAFinalDetectionEndsTheChainBeforeTheAttemptIsRecorded(): void {
		$dispatcher = $this->createMock(SignalDispatcher::class);
		$dispatcher->expects($this->once())->method('dispatch')->with($this->isInstanceOf(FailedLogin::class))->willReturn(new Dispatch([], true));
		$dispatcher->expects($this->never())->method('runs');
		$recorder = $this->createMock(AttemptRecorder::class);
		$recorder->expects($this->never())->method('record');

		$this->listener($dispatcher, $recorder)->handle(new AnyLoginFailedEvent('alice', 'secret'));
	}

	public function testTheAttemptIsRecordedAndJudgedWhileACheckReadsIt(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$attempt = new AttemptRecord(AttemptKind::PasswordLogin, $source, 'aa', null, null, 'bb', ['bb'], time(), true);
		$dispatched = [];
		$dispatcher = $this->createMock(SignalDispatcher::class);
		$dispatcher->method('dispatch')->willReturnCallback(static function (object $signal) use (&$dispatched): Dispatch {
			$dispatched[] = $signal;
			return new Dispatch([], false);
		});
		$dispatcher->method('runs')->willReturn(true);
		$recorder = $this->createMock(AttemptRecorder::class);
		$recorder->expects($this->once())->method('record')->willReturn($attempt);

		$this->listener($dispatcher, $recorder)->handle(new AnyLoginFailedEvent('alice', 'secret'));
		$this->assertCount(2, $dispatched);
		$this->assertInstanceOf(FailedLogin::class, $dispatched[0]);
		$this->assertInstanceOf(FailedLoginAttempt::class, $dispatched[1]);
		$this->assertSame($attempt, $dispatched[1]->attempt);
	}

	public function testNoAttemptIsRecordedWhileNoCheckReadsIt(): void {
		$dispatcher = $this->createMock(SignalDispatcher::class);
		$dispatcher->expects($this->once())->method('dispatch')->willReturn(new Dispatch([], false));
		$dispatcher->method('runs')->willReturn(false);
		$recorder = $this->createMock(AttemptRecorder::class);
		$recorder->expects($this->never())->method('record');

		$this->listener($dispatcher, $recorder)->handle(new AnyLoginFailedEvent('alice', 'secret'));
	}

	public function testABypassListedSourceIsIgnoredEntirely(): void {
		$addresses = $this->createMock(RemoteAddressResolver::class);
		$addresses->method('current')->willReturn(SourceKey::fromIp('198.51.100.7'));
		$addresses->method('isBypassListed')->willReturn(true);
		$dispatcher = $this->createMock(SignalDispatcher::class);
		$dispatcher->expects($this->never())->method('dispatch');
		$recorder = $this->createMock(AttemptRecorder::class);
		$recorder->expects($this->never())->method('record');

		$this->listener($dispatcher, $recorder, addresses: $addresses)->handle(new AnyLoginFailedEvent('admin', 'secret'));
	}

	public function testAnEmailIsOnlyLookedUpForTheChecksThatCountPerAccountEvenWithAMemoryCache(): void {
		$dispatcher = $this->createMock(SignalDispatcher::class);
		$dispatcher->method('dispatch')->willReturn(new Dispatch([], false));
		$dispatcher->method('runs')->willReturnCallback(static fn (string $signal, ?string $detector = null): bool => $detector !== AccountUnderAttackDetector::class);
		$recorder = $this->createMock(AttemptRecorder::class);
		$recorder->expects($this->once())->method('record')->with(AttemptKind::PasswordLogin, $this->anything(), 'alice@example.com', null)
			->willReturn(new AttemptRecord(AttemptKind::PasswordLogin, SourceKey::fromIp('198.51.100.7'), 'aa', null, null, 'bb', ['bb'], time(), true));
		$users = $this->createMock(IUserManager::class);
		$users->method('getUserNameFromLoginName')->willReturnArgument(0);
		$users->expects($this->never())->method('getByEmail');

		$this->listener($dispatcher, $recorder, $users)->handle(new AnyLoginFailedEvent('alice@example.com', 'secret'));
	}

	private function listener(SignalDispatcher $dispatcher, AttemptRecorder $recorder, ?IUserManager $users = null, ?RemoteAddressResolver $addresses = null): FailedLoginListener {
		$appSettings = $this->createMock(AppSettings::class);
		$appSettings->method('isEnabled')->willReturn(true);
		if ($addresses === null) {
			$addresses = $this->createMock(RemoteAddressResolver::class);
			$addresses->method('current')->willReturn(SourceKey::fromIp('198.51.100.7'));
		}
		$users ??= $this->createMock(IUserManager::class);
		return new FailedLoginListener(
			$appSettings, $addresses, $dispatcher, $recorder, $this->createMock(RiskScorer::class),
			$users, $this->createMock(IRequest::class), $this->createMock(LoggerInterface::class),
			$this->createMock(FailedLoginStats::class),
			new EmailAccounts($users, new FixedCaches(new \OC\Memcache\ArrayCache())),
		);
	}
}
