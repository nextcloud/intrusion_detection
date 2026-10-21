<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Admin\SettingsTransfer;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\ProtectionLevel;
use OCA\IntrusionDetection\Config\ProtectionLevels;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Controller\AdminApiController;
use OCP\AppFramework\Http;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The protection level sets every limit and block duration in one
 * validated write, leaves modes and responses alone, and becomes "custom"
 * as soon as a limit is changed by hand.
 */
#[Group('DB')]
class ProtectionLevelTest extends IntegrationTestCase {
	private Settings $settings;
	private ProtectionLevels $levels;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = Server::get(Settings::class);
		$this->levels = Server::get(ProtectionLevels::class);
	}

	public function testStrictHalvesTheLimitsAndLengthensBlocksButKeepsModesAndResponses(): void {
		$this->settings->updateCheck(CredentialStuffing::ID, Mode::Observe, [], [ResponseType::NotifyAdmin]);

		$changes = $this->levels->apply(ProtectionLevel::Strict);

		$this->assertSame(ProtectionLevel::Strict, $this->settings->protectionLevel());
		$this->assertSame(5, $this->settings->paramInt(CredentialStuffing::ID, 'min_failures'));
		$this->assertSame(3, $this->settings->paramInt(CredentialStuffing::ID, 'min_names'), 'half of 5, rounded');
		$this->assertSame(600, $this->settings->paramInt(CredentialStuffing::ID, 'window'), 'windows stay');
		$this->assertSame(28800, $this->settings->getInt(GlobalSettings::BAN_DURATION_1));
		$this->assertSame(Mode::Observe, $this->settings->configuredMode(CredentialStuffing::ID));
		$this->assertSame([ResponseType::NotifyAdmin], $this->settings->responses(CredentialStuffing::ID));
		$this->assertSame(5, $changes['checks'][CredentialStuffing::ID]['min_failures']);
		$this->assertSame(28800, $changes['settings'][GlobalSettings::BAN_DURATION_1]);
		$this->assertArrayNotHasKey(GlobalSettings::PROTECTION_LEVEL, $changes['settings'], 'the level is internal state; the changed values are the change');
	}

	public function testRelaxedDoublesTheLimitsWithinTheirRangeAndRecommendedRestoresTheDefaults(): void {
		$this->levels->apply(ProtectionLevel::Relaxed);
		$this->assertSame(20, $this->settings->paramInt(CredentialStuffing::ID, 'min_failures'));
		$this->assertSame(7200, $this->settings->getInt(GlobalSettings::BAN_DURATION_1));
		$this->assertSame(10, $this->settings->paramInt('second_factor_failed', 'max_failures_hour'));
		$this->assertSame(6, $this->settings->paramInt('second_factor_failed', 'max_failures'));

		$this->levels->apply(ProtectionLevel::Recommended);
		$this->assertSame(ProtectionLevel::Recommended, $this->settings->protectionLevel());
		$this->assertSame(10, $this->settings->paramInt(CredentialStuffing::ID, 'min_failures'));
		$this->assertSame(14400, $this->settings->getInt(GlobalSettings::BAN_DURATION_1));
	}

	public function testAManualChangeOfALimitMakesTheLevelCustom(): void {
		$this->levels->apply(ProtectionLevel::Strict);
		$this->settings->updateCheck(CredentialStuffing::ID, null, ['window' => 900], null);
		$this->assertSame(ProtectionLevel::Strict, $this->settings->protectionLevel(), 'a time window is not part of the level');

		$this->settings->updateCheck(CredentialStuffing::ID, null, ['min_failures' => 7], null);
		$this->assertSame(ProtectionLevel::Custom, $this->settings->protectionLevel());
	}

	public function testAManualChangeOfABlockDurationOrAResetMakesTheLevelCustom(): void {
		$this->levels->apply(ProtectionLevel::Relaxed);
		$this->settings->updateGlobals([GlobalSettings::BAN_DURATION_2 => 3600]);
		$this->assertSame(ProtectionLevel::Custom, $this->settings->protectionLevel());

		$this->levels->apply(ProtectionLevel::Strict);
		$this->settings->resetCheck(CredentialStuffing::ID);
		$this->assertSame(ProtectionLevel::Custom, $this->settings->protectionLevel());
	}

	public function testResettingEverythingIsTheRecommendedLevel(): void {
		$this->levels->apply(ProtectionLevel::Strict);
		Server::get(SettingsTransfer::class)->resetAll();
		$this->assertSame(ProtectionLevel::Recommended, $this->settings->protectionLevel());
		$this->assertSame(10, $this->settings->paramInt(CredentialStuffing::ID, 'min_failures'));
	}

	public function testCustomCannotBeApplied(): void {
		$this->expectException(\OCA\IntrusionDetection\Check\InvalidParamException::class);
		$this->levels->apply(ProtectionLevel::Custom);
	}

	public function testTheEndpointSetsTheLevelAndReturnsTheChecks(): void {
		$users = Server::get(IUserManager::class);
		$admin = $users->get('ids_level_admin') ?? $users->createUser('ids_level_admin', 'Ids-Test-Password-2026');
		Server::get(IUserSession::class)->setUser($admin);
		try {
			$controller = (new Application())->getContainer()->get(AdminApiController::class);
			$this->assertSame(['level' => 'recommended'], $controller->protectionLevel()->getData());

			$response = $controller->updateProtectionLevel('strict');
			$this->assertSame(Http::STATUS_OK, $response->getStatus());
			$data = $response->getData();
			$this->assertSame('strict', $data['level']);
			$check = array_values(array_filter($data['checks']['checks'], static fn (array $c): bool => $c['id'] === CredentialStuffing::ID))[0];
			$this->assertSame(5, array_column($check['params'], 'value', 'name')['min_failures']);

			$this->assertSame(Http::STATUS_BAD_REQUEST, $controller->updateProtectionLevel('custom')->getStatus());
			$this->assertSame(Http::STATUS_BAD_REQUEST, $controller->updateProtectionLevel('paranoid')->getStatus());
			$this->assertSame(ProtectionLevel::Strict, $this->settings->protectionLevel(), 'a refused level changes nothing');

			// The level is changed through its own endpoint only, and not shown as a setting.
			$this->assertSame(Http::STATUS_BAD_REQUEST, $controller->updateSettings([GlobalSettings::PROTECTION_LEVEL => 'relaxed'])->getStatus());
			$this->assertNotContains(GlobalSettings::PROTECTION_LEVEL, array_column($controller->settings()->getData()['settings'], 'name'));
		} finally {
			Server::get(IUserSession::class)->setUser(null);
			$admin->delete();
		}
	}
}
