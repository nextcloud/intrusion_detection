<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Blocklist\StateStore;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffingDetector;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Definition\ProtectionLevel;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Notification\DigestSender;
use OCA\IntrusionDetection\Repair\MoveInternalState;
use OCA\IntrusionDetection\State\AppState;
use OCA\IntrusionDetection\State\HotState;
use OCP\Migration\IOutput;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * An installation of an earlier version keeps its internal state in the app
 * config; after the upgrade it is in ids_state, and the app reads it there.
 */
#[Group('DB')]
class MoveInternalStateTest extends IntegrationTestCase {
	private const NOW = 1_800_000_000;

	public function testEveryValueMovesAndTheOldKeysAreDeleted(): void {
		$app = Application::APP_ID;
		$this->appConfig->setValueInt($app, AppState::INSTALLED_AT, self::NOW - 86400);
		$this->appConfig->setValueInt($app, LearningService::STARTED_STATE, self::NOW - 3600);
		$this->appConfig->setValueInt($app, LearningService::NOTICE_STATE, self::NOW - 60);
		$this->appConfig->setValueString($app, StateStore::STATE, '{"corp":{"version":3}}');
		$this->appConfig->setValueInt($app, CredentialStuffingDetector::DISTRIBUTED_UNTIL_STATE, self::NOW + 600);
		$this->appConfig->setValueInt($app, CredentialStuffingDetector::DISTRIBUTED_DETECTION_STATE, 42);
		$this->appConfig->setValueString($app, DigestSender::STATE, '{"period":1799999000,"sentAt":1799999100,"result":"sent","recipients":2,"failed":0,"withoutEmail":0}');
		$this->appConfig->setValueString($app, Settings::LEVEL_STATE, ProtectionLevel::Strict->value);
		$this->appConfig->setValueInt($app, HotState::DECOY_COUNT, 2);

		$this->repair();

		$this->assertSame([], array_values(array_intersect($this->appConfig->getKeys($app), MoveInternalState::MOVED)), 'no internal state is left in the app config');
		$this->assertSame(2, Server::get(HotState::class)->decoyCount(), 'values read on every request stay in the app config');
		$state = Server::get(AppState::class);
		$this->assertSame(self::NOW - 86400, $state->getInt(AppState::INSTALLED_AT));
		$this->assertSame(self::NOW - 3600, $state->getInt(LearningService::STARTED_STATE));
		$this->assertSame(self::NOW - 60, $state->getInt(LearningService::NOTICE_STATE));
		$this->assertSame(self::NOW + 600, $state->getInt(CredentialStuffingDetector::DISTRIBUTED_UNTIL_STATE));
		$this->assertSame(42, $state->getInt(CredentialStuffingDetector::DISTRIBUTED_DETECTION_STATE));
		$this->assertSame(3, Server::get(StateStore::class)->get('corp')->version);
		$this->assertSame(['period' => 1799999000, 'sentAt' => 1799999100, 'result' => 'sent', 'recipients' => 2, 'failed' => 0], Server::get(DigestSender::class)->overview(null)['last']);
		$this->assertSame(ProtectionLevel::Strict, Server::get(Settings::class)->protectionLevel());
	}

	public function testAValueAlreadyMovedIsKeptAndARepeatChangesNothing(): void {
		Server::get(AppState::class)->setInt(AppState::INSTALLED_AT, self::NOW);
		$this->appConfig->setValueInt(Application::APP_ID, AppState::INSTALLED_AT, self::NOW - 86400);

		$this->repair();
		$this->repair();

		$this->assertSame(self::NOW, Server::get(AppState::class)->getInt(AppState::INSTALLED_AT));
		$this->assertNotContains(AppState::INSTALLED_AT, $this->appConfig->getKeys(Application::APP_ID));
	}

	private function repair(): void {
		Server::get(MoveInternalState::class)->run($this->createMock(IOutput::class));
	}
}
