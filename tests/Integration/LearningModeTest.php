<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\AccountLocked;
use OCA\IntrusionDetection\Check\Checks\AdminChange;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\DecoyCredential;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Settings;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

#[Group('DB')]
class LearningModeTest extends IntegrationTestCase {
	private Settings $settings;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = Server::get(Settings::class);
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);
		$this->settings->setMode(AdminChange::ID, Mode::Protect);
	}

	public function testChecksThatOnlyNotifyActWhileLearning(): void {
		foreach ([AdminChange::ID, AccountLocked::ID, StepUpRefused::ID] as $checkId) {
			$state = $this->settings->modeState($checkId);
			$this->assertSame(Mode::Protect, $state->effective, $checkId);
			$this->assertNull($state->reason, $checkId);
			$this->assertTrue($this->settings->actsWhileLearning($checkId), $checkId);
		}
	}

	public function testChecksThatBlockOnlyObserveWhileLearning(): void {
		$state = $this->settings->modeState(CredentialStuffing::ID);
		$this->assertSame(Mode::Observe, $state->effective);
		$this->assertSame(ModeState::REASON_LEARNING, $state->reason);
	}

	public function testTheDecoySwitchGatesOnlyDecoys(): void {
		$this->settings->setGlobal(GlobalSettings::LEARNING_DECOYS_ACT, false);
		$this->assertSame(Mode::Observe, $this->settings->effectiveMode(DecoyCredential::ID));
		$this->assertSame(Mode::Protect, $this->settings->effectiveMode(AdminChange::ID), 'Admin change alerts do not depend on the decoy switch');

		$this->settings->setGlobal(GlobalSettings::LEARNING_DECOYS_ACT, true);
		$this->assertSame(Mode::Protect, $this->settings->effectiveMode(DecoyCredential::ID));
	}

	public function testOnlyNotifyingChecksAreKnownByTheirResponses(): void {
		$registry = Server::get(CheckRegistry::class);
		$this->assertTrue($registry->get(AdminChange::ID)->onlyNotifies());
		$this->assertTrue($registry->get(AccountLocked::ID)->onlyNotifies());
		$this->assertFalse($registry->get(CredentialStuffing::ID)->onlyNotifies());
		$this->assertFalse($registry->get(DecoyCredential::ID)->onlyNotifies());
	}
}
