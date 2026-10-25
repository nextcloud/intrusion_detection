<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\NewLogin\NewLogin;
use OCA\IntrusionDetection\Check\Checks\NewLogin\NewLoginDetector;
use OCA\IntrusionDetection\Check\Checks\NewLogin\NewLoginFacts;
use OCA\IntrusionDetection\Check\Checks\SecondFactorFailed\SecondFactorFailed;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Listener\Login\HistoryStep;
use OCA\IntrusionDetection\Listener\Login\KnownDeviceStep;
use OCA\IntrusionDetection\Listener\Login\NewLoginStep;
use OCA\IntrusionDetection\Listener\Login\StepUpStep;
use OCA\IntrusionDetection\LoginHistory\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\LoginHistory\SignInHistory;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\WasThisYou\Questions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;
use OCP\Server;
use OCP\User\Events\UserLoggedInEvent;
use PHPUnit\Framework\Attributes\Group;

/**
 * A person's login from a device and a network that are both new to the
 * account, which nothing else asked or told them about, tells them and asks
 * "Was this you?".
 */
#[Group('DB')]
class NewLoginTest extends StepUpTestCase {
	private const CHROME_MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';
	private const FIREFOX_WINDOWS = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0';

	private IUser $alice;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-new-alice');
		$this->headers['User-Agent'] = self::FIREFOX_WINDOWS;
		$this->remoteAddress = '203.0.113.9';
	}

	public function testALoginFromANewDeviceOnANewNetworkTellsTheUserAndAsks(): void {
		$this->usualLogins($this->alice);

		$this->newLogin($this->alice);

		$detections = $this->detectionsOf(NewLogin::ID);
		$this->assertCount(1, $detections);
		$detection = $detections[0];
		$this->assertSame('203.0.113.9', $detection->getIp());
		$facts = NewLoginFacts::fromArray(DetectionFacts::of($detection)->facts);
		$this->assertSame(['firefox', 'windows', true], [$facts->family, $facts->platform, $facts->typedPassword]);
		$questions = Server::get(Questions::class);
		$this->assertTrue($questions->isOpen($detection));
		$this->assertTrue($questions->involvesPassword($detection), '"No" also asks for a new password');
		$this->assertTrue(Server::get(UserMessages::class)->tellsUser($detection));
		$this->assertTrue($detection->isEnforced());
		$this->assertContains((string)$detection->getId(), $this->linker()->waiting($this->alice->getUID()), 'It waits for the session, so that "No" ends it');

	}

	public function testOnlyBothNewTogetherCount(): void {
		$this->usualLogins($this->alice);

		$this->headers['User-Agent'] = self::CHROME_MAC;
		$this->newLogin($this->alice);
		$this->assertSame([], $this->detectionsOf(NewLogin::ID), 'The usual device on a new network');

		$this->headers['User-Agent'] = self::FIREFOX_WINDOWS;
		$this->remoteAddress = '192.0.2.77';
		$this->newLogin($this->alice);
		$this->assertSame([], $this->detectionsOf(NewLogin::ID), 'A new device on the usual network');

		Server::get(LoginHistoryMapper::class)->insert($this->alice->getUID(), time() - 3600, SourceKey::fromIp('198.51.100.20'), self::FIREFOX_WINDOWS, LoginHistory::METHOD_PASSWORD, false, LoginHistory::CONFIRMED_BY_NONE, null, null);
		$this->remoteAddress = '203.0.113.9';
		$this->newLogin($this->alice);
		$this->assertSame([], $this->detectionsOf(NewLogin::ID), 'Once a login from the device went through, it is no longer new');
	}

	public function testNeverWhileTheHistoryIsYoungerThanItsWindow(): void {
		$this->usualLogins($this->alice, old: false);

		$this->newLogin($this->alice);

		$this->assertSame([], $this->detectionsOf(NewLogin::ID));
	}

	public function testNeverWhenTheLoginWasAskedForConfirmation(): void {
		$this->usualLogins($this->alice);
		Server::get(FlaggedSources::class)->flagNetwork(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_USER_DENIED);

		$this->newLogin($this->alice);

		$this->assertNotNull($this->stepUp());
		$this->assertSame([], $this->detectionsOf(NewLogin::ID));
	}

	public function testNeverWhenAnotherDetectionOfTheLoginTellsTheUser(): void {
		$this->usualLogins($this->alice);
		$told = $this->storeDetection(new DetectionDraft(checkId: SecondFactorFailed::ID, source: SourceKey::fromIp($this->remoteAddress), uid: $this->alice->getUID()));
		$this->linker()->await($this->alice->getUID(), [(string)$told->getId()]);

		$this->newLogin($this->alice);

		$this->assertSame([], $this->detectionsOf(NewLogin::ID));
	}

	public function testNeverForAnAccountWithASecondFactor(): void {
		$this->usualLogins($this->alice);
		$this->hasSecondFactor = true;

		$this->newLogin($this->alice);

		$this->assertSame([], $this->detectionsOf(NewLogin::ID));
	}

	public function testLearningModeOnlyRecordsIt(): void {
		$this->usualLogins($this->alice);
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);

		$this->newLogin($this->alice);

		$detections = $this->detectionsOf(NewLogin::ID);
		$this->assertCount(1, $detections);
		$this->assertFalse($detections[0]->isEnforced(), 'Nobody is told while Nextcloud learns');
	}

	/**
	 * Logins that went through with Chrome on macOS from 192.0.2.0/24, on
	 * the three days before; with one 40 days ago, so that the history
	 * reaches back further than the habit window.
	 */
	private function usualLogins(IUser $user, bool $old = true): void {
		$mapper = Server::get(LoginHistoryMapper::class);
		$now = time();
		foreach ($old ? [1, 2, 3, 40] : [1, 2, 3] as $days) {
			$mapper->insert($user->getUID(), $now - $days * 86400, SourceKey::fromIp('192.0.2.10'), self::CHROME_MAC, LoginHistory::METHOD_PASSWORD, false, LoginHistory::CONFIRMED_BY_NONE, null, null);
		}
	}

	private function newLogin(IUser $user): void {
		if ($this->session->id === null) {
			$this->session->id = bin2hex(random_bytes(32));
		}
		$this->sessionUser = $user;
		$detector = new NewLoginDetector(
			Server::get(SignInHistory::class),
			$this->history(),
			$this->secondFactors(),
			$this->linker(),
			Server::get(DetectionMapper::class),
			Server::get(UserMessages::class),
			$this->appSettings(),
			Server::get(ITimeFactory::class),
		);
		$step = new NewLoginStep($this->dispatcher([NewLoginDetector::class => $detector], $this->engine()), $this->linker());
		$listener = $this->loginListener([StepUpStep::class, KnownDeviceStep::class, NewLoginStep::class, HistoryStep::class], instances: [NewLoginStep::class => $step]);
		$listener->handle(new UserLoggedInEvent($user, $user->getUID(), self::PASSWORD, false));
	}
}
