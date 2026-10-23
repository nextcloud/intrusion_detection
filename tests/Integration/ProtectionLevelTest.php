<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Admin\SettingsTransfer;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffing;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Configure\ProtectionLevels;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Controller\CheckApiController;
use OCA\IntrusionDetection\Controller\SettingsApiController;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ProtectionLevel;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Tests\Unit\Controller\AnswersLikeTheApi;
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
	use AnswersLikeTheApi;

	private ProtectionLevels $levels;

	protected function setUp(): void {
		parent::setUp();
		$this->levels = Server::get(ProtectionLevels::class);
	}

	public function testStrictHalvesTheLimitsAndLengthensBlocksButKeepsModesAndResponses(): void {
		$this->settingsEditor()->updateCheck(CredentialStuffing::ID, Mode::Observe, [], [ResponseType::NotifyAdmin]);

		$changes = $this->levels->apply(ProtectionLevel::Strict, 'test');

		$this->assertSame(ProtectionLevel::Strict, $this->settingsEditor()->protectionLevel());
		$this->assertSame(5, $this->checkSettings()->paramInt(CredentialStuffing::ID, 'min_failures'));
		$this->assertSame(3, $this->checkSettings()->paramInt(CredentialStuffing::ID, 'min_names'), 'half of 5, rounded');
		$this->assertSame(600, $this->checkSettings()->paramInt(CredentialStuffing::ID, 'window'), 'windows stay');
		$this->assertSame(28800, $this->appSettings()->banDurations()[1]);
		$this->assertSame(Mode::Observe, $this->checkSettings()->configuredMode(CredentialStuffing::ID));
		$this->assertSame([ResponseType::NotifyAdmin], $this->checkSettings()->responses(CredentialStuffing::ID));
		$this->assertSame(5, $changes['checks'][CredentialStuffing::ID]['min_failures']);
		$this->assertSame(28800, $changes['settings'][GlobalSettings::BAN_DURATION_1]);
		$this->assertArrayNotHasKey(SettingsEditor::LEVEL_STATE, $changes['settings'], 'the level is internal state; the changed values are the change');
	}

	public function testRelaxedDoublesTheLimitsWithinTheirRangeAndRecommendedRestoresTheDefaults(): void {
		$this->levels->apply(ProtectionLevel::Relaxed, 'test');
		$this->assertSame(20, $this->checkSettings()->paramInt(CredentialStuffing::ID, 'min_failures'));
		$this->assertSame(7200, $this->appSettings()->banDurations()[1]);
		$this->assertSame(10, $this->checkSettings()->paramInt('second_factor_failed', 'max_failures_hour'));
		$this->assertSame(6, $this->checkSettings()->paramInt('second_factor_failed', 'max_failures'));

		$this->levels->apply(ProtectionLevel::Recommended, 'test');
		$this->assertSame(ProtectionLevel::Recommended, $this->settingsEditor()->protectionLevel());
		$this->assertSame(10, $this->checkSettings()->paramInt(CredentialStuffing::ID, 'min_failures'));
		$this->assertSame(14400, $this->appSettings()->banDurations()[1]);
	}

	public function testAManualChangeOfALimitMakesTheLevelCustom(): void {
		$this->levels->apply(ProtectionLevel::Strict, 'test');
		$this->settingsEditor()->updateCheck(CredentialStuffing::ID, null, ['window' => 900], null);
		$this->assertSame(ProtectionLevel::Strict, $this->settingsEditor()->protectionLevel(), 'a time window is not part of the level');

		$this->settingsEditor()->updateCheck(CredentialStuffing::ID, null, ['min_failures' => 7], null);
		$this->assertSame(ProtectionLevel::Custom, $this->settingsEditor()->protectionLevel());
	}

	public function testAManualChangeOfABlockDurationOrAResetMakesTheLevelCustom(): void {
		$this->levels->apply(ProtectionLevel::Relaxed, 'test');
		$this->settingsEditor()->updateGlobals([GlobalSettings::BAN_DURATION_2 => 3600]);
		$this->assertSame(ProtectionLevel::Custom, $this->settingsEditor()->protectionLevel());

		$this->levels->apply(ProtectionLevel::Strict, 'test');
		$this->settingsEditor()->resetCheck(CredentialStuffing::ID);
		$this->assertSame(ProtectionLevel::Custom, $this->settingsEditor()->protectionLevel());
	}

	public function testResettingTheOnlyChangedCheckRestoresTheLevel(): void {
		$this->settingsEditor()->updateCheck(CredentialStuffing::ID, null, ['min_failures' => 7], null);
		$this->assertSame(ProtectionLevel::Custom, $this->settingsEditor()->protectionLevel());

		$this->settingsEditor()->resetCheck(CredentialStuffing::ID);
		$this->assertSame(ProtectionLevel::Recommended, $this->settingsEditor()->protectionLevel(), 'every limit is at its default again');
	}

	public function testResettingACheckKeepsCustomWhileAnotherLimitDiffers(): void {
		$this->settingsEditor()->updateCheck(CredentialStuffing::ID, null, ['min_failures' => 7], null);
		$this->settingsEditor()->updateGlobals([GlobalSettings::BAN_DURATION_2 => 3600]);
		$this->settingsEditor()->resetCheck(CredentialStuffing::ID);
		$this->assertSame(ProtectionLevel::Custom, $this->settingsEditor()->protectionLevel());
	}

	public function testResettingEverythingIsTheRecommendedLevel(): void {
		$this->levels->apply(ProtectionLevel::Strict, 'test');
		Server::get(SettingsTransfer::class)->resetAll('test');
		$this->assertSame(ProtectionLevel::Recommended, $this->settingsEditor()->protectionLevel());
		$this->assertSame(10, $this->checkSettings()->paramInt(CredentialStuffing::ID, 'min_failures'));
	}

	public function testCustomCannotBeApplied(): void {
		$this->expectException(\OCA\IntrusionDetection\Definition\InvalidParamException::class);
		$this->levels->apply(ProtectionLevel::Custom, 'test');
	}

	public function testTheEndpointSetsTheLevelAndReturnsTheChecks(): void {
		$users = Server::get(IUserManager::class);
		$admin = $users->get('ids_level_admin') ?? $users->createUser('ids_level_admin', 'Ids-Test-Password-2026');
		Server::get(IUserSession::class)->setUser($admin);
		try {
			$container = (new Application())->getContainer();
			$this->assertSame(['level' => 'recommended'], $container->get(CheckApiController::class)->protectionLevel()->getData());

			$response = $container->get(CheckApiController::class)->updateProtectionLevel('strict');
			$this->assertSame(Http::STATUS_OK, $response->getStatus());
			$data = $response->getData();
			$this->assertSame('strict', $data['level']);
			$check = array_values(array_filter($data['checks']['checks'], static fn (array $c): bool => $c['id'] === CredentialStuffing::ID))[0];
			$this->assertSame(5, array_column($check['params'], 'value', 'name')['min_failures']);

			$this->assertSame(Http::STATUS_BAD_REQUEST, $this->answer(fn () => $container->get(CheckApiController::class)->updateProtectionLevel('custom'))->getStatus());
			$this->assertSame(Http::STATUS_BAD_REQUEST, $this->answer(fn () => $container->get(CheckApiController::class)->updateProtectionLevel('paranoid'))->getStatus());
			$this->assertSame(ProtectionLevel::Strict, $this->settingsEditor()->protectionLevel(), 'a refused level changes nothing');

			// The level is changed through its own endpoint only, and not shown as a setting.
			$this->assertSame(Http::STATUS_BAD_REQUEST, $this->answer(fn () => $container->get(SettingsApiController::class)->updateSettings([SettingsEditor::LEVEL_STATE => 'relaxed']))->getStatus());
			$this->assertNotContains(SettingsEditor::LEVEL_STATE, array_column($container->get(SettingsApiController::class)->settings()->getData()['settings'], 'name'));
		} finally {
			Server::get(IUserSession::class)->setUser(null);
			$admin->delete();
		}
	}
}
