<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Command\Checks\Set;
use OCA\IntrusionDetection\Command\Status;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Controller\CheckApiController;
use OCA\IntrusionDetection\Controller\SettingsApiController;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\SetupCheck\ConfigLockCheck;
use OCP\AppFramework\Http;
use OCP\AppFramework\IAppContainer;
use OCP\IConfig;
use OCP\IL10N;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * `'intrusion_detection.locked' => true` in config.php holds the protective
 * settings at their safest values: intrusion detection on, the admin
 * change check in Protect, and the approval of new administrators on.
 * Neither occ, the API nor "Reset all settings" can change them.
 */
#[Group('DB')]
class ConfigLockTest extends AdminChangeTestCase {
	use OcsPipeline;

	private IAppContainer $container;

	protected function setUp(): void {
		parent::setUp();
		Server::get(IConfig::class)->setSystemValue(AppSettings::LOCK, true);
		Server::get(IUserSession::class)->setUser($this->user($this->alice));
		$this->container = (new Application())->getContainer();
	}

	protected function tearDown(): void {
		Server::get(IConfig::class)->deleteSystemValue(AppSettings::LOCK);
		Server::get(IUserSession::class)->setUser(null);
		parent::tearDown();
	}

	public function testTheProtectiveSettingsReadAsTheirSafestValues(): void {
		$this->appConfig->setValueBool(Application::APP_ID, GlobalSettings::ENABLED, false);
		$this->appConfig->setValueBool(Application::APP_ID, GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL, false);
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode(AdminChange::ID), Mode::Off->value);

		$this->assertTrue($this->appSettings()->isEnabled(), 'occ config:app:set cannot switch it off');
		$this->assertTrue($this->appSettings()->adminChangeRequireApproval());
		$this->assertSame(Mode::Protect, $this->checkSettings()->configuredMode(AdminChange::ID));
		$this->assertSame(Mode::Protect, $this->checkSettings()->effectiveMode(AdminChange::ID));
	}

	public function testOccCannotChangeALockedSetting(): void {
		$tester = new CommandTester(Server::get(Set::class));
		$this->assertNotSame(0, $tester->execute(['check' => AdminChange::ID, '--mode' => Mode::Off->value]));
		$this->assertStringContainsString('locked', $tester->getDisplay());
		$this->assertSame(Mode::Protect, $this->checkSettings()->configuredMode(AdminChange::ID));
		$this->assertSame(Mode::Protect->value, $this->appConfig->getValueString(Application::APP_ID, Keys::mode(AdminChange::ID)), 'Nothing was stored');
	}

	public function testTheApiCannotChangeALockedSetting(): void {
		$answer = $this->ocs($this->container->get(SettingsApiController::class), 'updateSettings', [[GlobalSettings::ENABLED => false]]);
		$this->assertSame(Http::STATUS_BAD_REQUEST, $answer['status']);
		$this->assertSame('locked', $answer['data']['reason']);

		$answer = $this->ocs($this->container->get(SettingsApiController::class), 'updateSettings', [[GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL => false]]);
		$this->assertSame('locked', $answer['data']['reason']);

		$answer = $this->ocs($this->container->get(CheckApiController::class), 'updateCheck', [AdminChange::ID, Mode::Observe->value]);
		$this->assertSame(Http::STATUS_BAD_REQUEST, $answer['status']);
		$this->assertSame('locked', $answer['data']['reason']);
		$this->assertSame([], Server::get(ApprovalService::class)->list(true, 10, Approval::KIND_SETTINGS), 'Nothing waits for approval either');
	}

	public function testResetAllSettingsCannotChangeALockedSetting(): void {
		$this->appConfig->setValueBool(Application::APP_ID, GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL, true);
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::BAN_DURATION_1, 7200);

		$answer = $this->ocs($this->container->get(SettingsApiController::class), 'resetSettings');
		$this->assertSame(Http::STATUS_OK, $answer['status'], 'Not held for approval: the lock keeps the approval on');
		$this->assertSame(14400, $this->appSettings()->banDurations()[1], 'Every other setting is reset');
		$this->assertTrue($this->appSettings()->adminChangeRequireApproval());
		$this->assertSame(Mode::Protect->value, $this->appConfig->getValueString(Application::APP_ID, Keys::mode(AdminChange::ID)), 'The stored mode is left alone');
		$this->assertTrue($this->appConfig->getValueBool(Application::APP_ID, GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL), 'The stored approval is left alone');
	}

	public function testTheLockShowsInTheStatusAndOnTheAdminPage(): void {
		$tester = new CommandTester(Server::get(Status::class));
		$tester->execute([]);
		$this->assertStringContainsString('Locked in config.php', $tester->getDisplay());
		$tester->execute(['--output' => 'json']);
		$this->assertTrue(json_decode($tester->getDisplay(), true)['locked']);

		$finding = Server::get(ConfigLockCheck::class)->finding($this->l());
		$this->assertNotNull($finding);
		$this->assertSame('settings_locked', $finding->id);

		$settings = $this->ocs($this->container->get(SettingsApiController::class), 'settings')['data']['settings'];
		$locked = array_column(array_filter($settings, static fn (array $s): bool => $s['locked']), 'name');
		sort($locked);
		$this->assertSame([GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL, GlobalSettings::ENABLED], $locked);
	}

	private function l(): IL10N {
		return Server::get(IFactory::class)->get(Application::APP_ID, 'en');
	}
}
