<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\Lockdown;
use OCA\IntrusionDetection\Db\LockdownMapper;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Lockdown\LockdownService;
use OCA\IntrusionDetection\Lockdown\LockdownState;
use OCA\IntrusionDetection\Notification\LockdownNotices;
use OCP\L10N\IFactory;
use OCP\Notification\IManager as INotificationManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Lockdown and the login checks, through the failed-login listener: the
 * automatic start on a distributed attack, and the lowered limits.
 */
#[Group('DB')]
class LockdownAttacksTest extends LoginFailureTestCase {
	protected function setUp(): void {
		parent::setUp();
		Server::get(INotificationManager::class)->registerApp(CapturingNotificationApp::class);
		CapturingNotificationApp::$notifications = [];
	}

	public function testADistributedAttackStartsALockdownWhenThatIsOn(): void {
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_AUTO_ON_DISTRIBUTED, true);
		$this->distributedAttack();

		$state = Server::get(LockdownState::class);
		$this->assertTrue($state->isActive());
		$this->assertEqualsWithDelta(time() + LockdownService::AUTO_DURATION, $state->until(), 2, 'For 2 hours');
		$this->assertSame(Lockdown::ACTOR_AUTOMATIC, $state->info()['startedBy']);
		$entry = Server::get(LockdownMapper::class)->latest(1)[0];
		$distributed = array_values(array_filter($this->detectionsOf(CredentialStuffing::ID), static fn ($d): bool => ($d->getExplanationData()['facts']['distributed'] ?? false) === true));
		$this->assertSame($distributed[0]->getId(), $entry->getDetectionId(), 'The lockdown points to the attack');
		$this->assertNotSame([], array_filter(CapturingNotificationApp::$notifications, static fn ($n): bool => $n->getSubject() === LockdownNotices::SUBJECT_STARTED));
	}

	public function testItIsOffByDefault(): void {
		$this->distributedAttack();
		$this->assertFalse(Server::get(LockdownState::class)->isActive());
	}

	public function testAnAttackThatIsOnlyObservedStartsNothing(): void {
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_AUTO_ON_DISTRIBUTED, true);
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);
		$this->distributedAttack();
		$this->assertFalse(Server::get(LockdownState::class)->isActive());
	}

	public function testARunningLockdownThatEndsSoonerIsExtendedToTwoHours(): void {
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_AUTO_ON_DISTRIBUTED, true);
		Server::get(LockdownService::class)->start(3600, 'by hand', 'admin');
		$this->distributedAttack();
		$state = Server::get(LockdownState::class);
		$this->assertEqualsWithDelta(time() + LockdownService::AUTO_DURATION, $state->until(), 2);
		$this->assertSame('admin', $state->info()['startedBy'], 'Still the same lockdown');
	}

	public function testDuringLockdownTheLimitsAreHalved(): void {
		Server::get(LockdownService::class)->start(3600, '', 'admin');
		// 10 failures for 5 accounts by default; halved: 5 failures for 3 accounts.
		for ($i = 1; $i <= 5; $i++) {
			$this->failLogin('198.51.100.7', 'user' . ($i % 3));
		}
		$detections = $this->detectionsOf(CredentialStuffing::ID);
		$this->assertCount(1, $detections);
		$narrative = Server::get(NarrativeBuilder::class)->build($detections[0], Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		$this->assertStringContainsString('because lockdown mode was on', implode(' ', $narrative->happened));
	}

	public function testWithoutLockdownTheSameFailuresStayBelowTheLimit(): void {
		for ($i = 1; $i <= 5; $i++) {
			$this->failLogin('198.51.100.7', 'user' . ($i % 3));
		}
		$this->assertSame([], $this->detectionsOf(CredentialStuffing::ID));
	}

	private function distributedAttack(): void {
		$this->settings->setParam(CredentialStuffing::ID, 'min_failures', 1000);
		for ($i = 0; $i < 99; $i++) {
			$this->storeAttempt('192.0.2.' . ($i % 25 + 1), 'victim' . ($i % 25), at: time() - 120);
		}
		$this->failLogin('192.0.2.1', 'victim99');
	}
}
