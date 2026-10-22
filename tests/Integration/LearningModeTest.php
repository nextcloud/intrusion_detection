<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\AccountLocked\AccountLocked;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\DecoyCredential\DecoyCredential;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused\StepUpRefused;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Definition\Mode;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

#[Group('DB')]
class LearningModeTest extends IntegrationTestCase {
	protected function setUp(): void {
		parent::setUp();
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);
		$this->settingsEditor()->setMode(AdminChange::ID, Mode::Protect);
	}

	public function testChecksThatOnlyNotifyActWhileLearning(): void {
		foreach ([AdminChange::ID, AccountLocked::ID, StepUpRefused::ID] as $checkId) {
			$state = $this->checkSettings()->modeState($checkId);
			$this->assertSame(Mode::Protect, $state->effective, $checkId);
			$this->assertNull($state->reason, $checkId);
			$this->assertTrue($this->checkSettings()->actsWhileLearning($checkId), $checkId);
		}
	}

	public function testChecksThatBlockOnlyObserveWhileLearning(): void {
		$state = $this->checkSettings()->modeState(CredentialStuffing::ID);
		$this->assertSame(Mode::Observe, $state->effective);
		$this->assertSame(ModeState::REASON_LEARNING, $state->reason);
	}

	public function testDecoysAndAdminChangeAlertsActWhileLearning(): void {
		$this->assertSame(Mode::Protect, $this->checkSettings()->effectiveMode(DecoyCredential::ID));
		$this->assertSame(Mode::Protect, $this->checkSettings()->effectiveMode(AdminChange::ID));
	}

	public function testOnlyNotifyingChecksAreKnownByTheirResponses(): void {
		$registry = Server::get(CheckRegistry::class);
		$this->assertTrue($registry->get(AdminChange::ID)->onlyNotifies());
		$this->assertTrue($registry->get(AccountLocked::ID)->onlyNotifies());
		$this->assertFalse($registry->get(CredentialStuffing::ID)->onlyNotifies());
		$this->assertFalse($registry->get(DecoyCredential::ID)->onlyNotifies());
	}
}
