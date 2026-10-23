<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Listener;

use OCA\IntrusionDetection\Check\Checks\LoginFlowMismatch\LoginFlowMismatchDetector;
use OCA\IntrusionDetection\Check\Checks\ResetProbing\ResetProbingDetector;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce\ShareBruteforceDetector;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Listener\LoginFlowGrantedListener;
use OCA\IntrusionDetection\Listener\ResetRequestedListener;
use OCA\IntrusionDetection\Listener\ShareAccessFailedListener;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\IAcceptedLogins;
use OCA\IntrusionDetection\Response\ResetMailSuppressor;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ShareAccessFailed;
use OCA\IntrusionDetection\Signal\SignalDispatcher;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Events\LoginFlowV2GrantedEvent;
use OCP\Authentication\Token\IToken;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Security\Events\PasswordResetRequestedEvent;
use OCP\Share\Events\ShareLinkAccessFailedEvent;
use OCP\Share\IShare;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * The listeners for share link failures, reset requests and granted login
 * flows: they skip all work when their check is off, ignore allowlisted
 * sources, and never break the request they listen to.
 */
class PublicEventListenersTest extends TestCase {
	private const TOKEN = 'SecretShareToken42';

	/** @var CheckSettings&MockObject */
	private CheckSettings $settings;
	/** @var RemoteAddressResolver&MockObject */
	private RemoteAddressResolver $addresses;
	/** @var AttemptRecorder&MockObject */
	private AttemptRecorder $recorder;
	/** @var LoggerInterface&MockObject */
	private LoggerInterface $logger;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = $this->createMock(CheckSettings::class);
		$this->addresses = $this->createMock(RemoteAddressResolver::class);
		$this->addresses->method('current')->willReturn(SourceKey::fromIp('198.51.100.7'));
		$this->recorder = $this->createMock(AttemptRecorder::class);
		$this->logger = $this->createMock(LoggerInterface::class);
	}

	public function testOffSkipsEveryListenerBeforeAnyWork(): void {
		$this->mode(Mode::Off);
		$this->addresses->expects($this->never())->method('current');
		$this->recorder->expects($this->never())->method($this->anything());

		$this->shareListener($this->createMock(ShareBruteforceDetector::class))->handle(new ShareLinkAccessFailedEvent(self::TOKEN, null, ShareLinkAccessFailedEvent::REASON_NOT_FOUND));
		$this->resetListener($this->createMock(ResetProbingDetector::class), $this->createMock(ResetMailSuppressor::class))->handle(new PasswordResetRequestedEvent('alice'));
		$detector = $this->createMock(LoginFlowMismatchDetector::class);
		$detector->expects($this->never())->method('detect');
		$this->flowListener($detector)->handle(new LoginFlowV2GrantedEvent($this->createMock(IToken::class), '203.0.113.5', time()));
	}

	public function testAllowlistedSourcesAreIgnored(): void {
		$this->mode(Mode::Protect);
		$this->addresses->method('isBypassListed')->willReturn(true);
		$this->recorder->expects($this->never())->method($this->anything());
		$this->shareListener($this->createMock(ShareBruteforceDetector::class))->handle(new ShareLinkAccessFailedEvent(self::TOKEN, null, ShareLinkAccessFailedEvent::REASON_NOT_FOUND));
		$this->resetListener($this->createMock(ResetProbingDetector::class), $this->createMock(ResetMailSuppressor::class))->handle(new PasswordResetRequestedEvent('alice'));
	}

	public function testOnlyTheTokenFingerprintIsRecordedForAnUnknownLink(): void {
		$this->mode(Mode::Protect);
		$attempt = $this->attempt(AttemptKind::UnknownShareToken);
		$this->recorder->expects($this->once())->method('recordUnknownShareToken')->with($this->anything(), self::TOKEN)->willReturn($attempt);
		$detector = $this->createMock(ShareBruteforceDetector::class);
		$detector->expects($this->once())->method('detect')->with($this->callback(static fn (ShareAccessFailed $s): bool => $s->attempt === $attempt && $s->share === null));
		$this->shareListener($detector)->handle(new ShareLinkAccessFailedEvent(self::TOKEN, null, ShareLinkAccessFailedEvent::REASON_NOT_FOUND));
	}

	public function testUnknownLinksOfLoggedInUsersAreRecordedWithTheirAccount(): void {
		$this->mode(Mode::Protect);
		$attempt = $this->attempt(AttemptKind::UnknownShareToken);
		$this->recorder->expects($this->once())->method('recordUnknownShareToken')->with($this->anything(), self::TOKEN, false, 'alice')->willReturn($attempt);
		$detector = $this->createMock(ShareBruteforceDetector::class);
		$detector->expects($this->once())->method('detect')->with($this->callback(static fn (ShareAccessFailed $s): bool => $s->attempt === $attempt));
		$this->shareListener($detector, loggedIn: true)->handle(new ShareLinkAccessFailedEvent(self::TOKEN, null, ShareLinkAccessFailedEvent::REASON_NOT_FOUND));
	}

	public function testAWrongPasswordOfALoggedInUserStillCounts(): void {
		$this->mode(Mode::Protect);
		$share = $this->createMock(IShare::class);
		$share->method('getId')->willReturn('42');
		$this->recorder->expects($this->once())->method('record')->willReturn($this->attempt(AttemptKind::WrongSharePassword));
		$detector = $this->createMock(ShareBruteforceDetector::class);
		$detector->expects($this->once())->method('detect')->with($this->callback(static fn (ShareAccessFailed $s): bool => $s->share !== null));
		$this->shareListener($detector, loggedIn: true)->handle(new ShareLinkAccessFailedEvent(self::TOKEN, $share, ShareLinkAccessFailedEvent::REASON_WRONG_PASSWORD));
	}

	public function testAWrongPasswordIsCountedPerShare(): void {
		$this->mode(Mode::Protect);
		$share = $this->createMock(IShare::class);
		$share->method('getId')->willReturn('42');
		$attempt = $this->attempt(AttemptKind::WrongSharePassword);
		$this->recorder->expects($this->once())->method('record')->with(AttemptKind::WrongSharePassword, $this->anything(), null, null, 42)->willReturn($attempt);
		$detector = $this->createMock(ShareBruteforceDetector::class);
		$detector->expects($this->once())->method('detect')->with($this->callback(static fn (ShareAccessFailed $s): bool => $s->attempt === $attempt && $s->share === $share));
		$this->shareListener($detector)->handle(new ShareLinkAccessFailedEvent(self::TOKEN, $share, ShareLinkAccessFailedEvent::REASON_WRONG_PASSWORD));
	}

	public function testSharesWithoutANumericIdAreNotCounted(): void {
		$this->mode(Mode::Protect);
		$share = $this->createMock(IShare::class);
		$share->method('getId')->willReturn('team:abc');
		$this->recorder->expects($this->never())->method('record');
		$this->shareListener($this->createMock(ShareBruteforceDetector::class))->handle(new ShareLinkAccessFailedEvent(self::TOKEN, $share, ShareLinkAccessFailedEvent::REASON_WRONG_PASSWORD));
	}

	public function testAFailingShareDetectorDoesNotBreakTheShareAccessAndLogsNoToken(): void {
		$this->mode(Mode::Protect);
		$this->recorder->method('recordUnknownShareToken')->willReturn($this->attempt(AttemptKind::UnknownShareToken));
		$detector = $this->createMock(ShareBruteforceDetector::class);
		$detector->method('detect')->willThrowException(new \RuntimeException('database gone'));
		$this->logger->expects($this->once())->method('error')->with($this->logicalNot($this->stringContains(self::TOKEN)), $this->callback(static fn (array $context): bool => !str_contains((string)json_encode(array_diff_key($context, ['exception' => 1])), self::TOKEN)));
		$this->shareListener($detector)->handle(new ShareLinkAccessFailedEvent(self::TOKEN, null, ShareLinkAccessFailedEvent::REASON_NOT_FOUND));
	}

	public function testHeldBackEmailsStayHeldBackWhenTheDetectorFails(): void {
		$this->mode(Mode::Protect);
		$this->recorder->method('record')->willReturn($this->attempt(AttemptKind::PasswordReset));
		$detector = $this->createMock(ResetProbingDetector::class);
		$detector->method('detect')->willThrowException(new \RuntimeException('database gone'));
		$suppressor = $this->createMock(ResetMailSuppressor::class);
		$suppressor->method('isSuppressed')->willReturn(true);
		$this->logger->expects($this->once())->method('error');

		$event = new PasswordResetRequestedEvent('alice');
		$this->resetListener($detector, $suppressor, 'alice')->handle($event);
		$this->assertTrue($event->isEmailPrevented());
	}

	public function testObserveNeverHoldsBackAnEmail(): void {
		$this->settings->method('modeState')->willReturn(new ModeState(Mode::Protect, Mode::Observe, ModeState::REASON_LEARNING));
		$this->recorder->method('record')->willReturn($this->attempt(AttemptKind::PasswordReset));
		$suppressor = $this->createMock(ResetMailSuppressor::class);
		$suppressor->expects($this->never())->method('isSuppressed');
		$event = new PasswordResetRequestedEvent('alice');
		$this->resetListener($this->createMock(ResetProbingDetector::class), $suppressor, 'alice')->handle($event);
		$this->assertFalse($event->isEmailPrevented());
	}

	public function testAFailingLoginFlowCheckDoesNotBreakTheGrant(): void {
		$this->mode(Mode::Protect);
		$detector = $this->createMock(LoginFlowMismatchDetector::class);
		$detector->method('detect')->willThrowException(new \RuntimeException('database gone'));
		$this->logger->expects($this->once())->method('error');
		$this->flowListener($detector)->handle(new LoginFlowV2GrantedEvent($this->createMock(IToken::class), '203.0.113.5', time()));
	}

	private function mode(Mode $mode): void {
		$this->settings->method('modeState')->willReturn(new ModeState($mode, $mode));
	}

	private function attempt(AttemptKind $kind): AttemptRecord {
		return new AttemptRecord($kind, SourceKey::fromIp('198.51.100.7'), null, null, null, null, [], time(), true);
	}

	private function shareListener(ShareBruteforceDetector $detector, bool $loggedIn = false): ShareAccessFailedListener {
		$session = $this->createMock(IUserSession::class);
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$session->method('getUser')->willReturn($loggedIn ? $user : null);
		return new ShareAccessFailedListener($this->dispatcher($detector), $this->addresses, $this->recorder, $this->createMock(IRequest::class), $session, $this->logger);
	}

	private function resetListener(ResetProbingDetector $detector, ResetMailSuppressor $suppressor, ?string $existingUid = null): ResetRequestedListener {
		$users = $this->createMock(IUserManager::class);
		if ($existingUid !== null) {
			$user = $this->createMock(IUser::class);
			$user->method('getUID')->willReturn($existingUid);
			$user->method('isEnabled')->willReturn(true);
			$users->method('get')->willReturnMap([[$existingUid, $user]]);
		}
		return new ResetRequestedListener($this->dispatcher($detector), $this->addresses, $this->recorder, $suppressor, $users, $this->createMock(IRequest::class), $this->logger, new \OCA\IntrusionDetection\Login\EmailAccounts($users, FixedCaches::none(), \OCP\Server::get(\OCA\IntrusionDetection\Crypto\Fingerprinter::class)), $this->createMock(KnownDevices::class), $this->createMock(IAcceptedLogins::class), $this->createMock(ITimeFactory::class));
	}

	private function flowListener(LoginFlowMismatchDetector $detector): LoginFlowGrantedListener {
		return new LoginFlowGrantedListener($this->dispatcher($detector), $this->addresses, $this->createMock(IRequest::class), $this->logger);
	}

	/**
	 * The dispatcher with the listener's detector, and an engine that records nothing.
	 */
	private function dispatcher(IDetector $detector): SignalDispatcher {
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturn($detector);
		return new SignalDispatcher($this->settings, $this->createMock(ResponseEngine::class), $container, $this->logger);
	}
}
