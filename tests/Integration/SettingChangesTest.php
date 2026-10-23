<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\AdminChange\WatchedSettings;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffing;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Configure\ProtectionLevels;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Controller\AdminApiController;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ProtectionLevel;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Event\SettingChangedEvent;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Tests\Unit\Controller\AnswersLikeTheApi;
use OCP\AppFramework\Http;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * What every kind of settings write reports: one SettingChangedEvent per
 * changed value, with the effective values before and after; refused
 * values in the admin API's error shape; and the own settings the config
 * watch compares.
 */
#[Group('DB')]
class SettingChangesTest extends IntegrationTestCase {
	use AnswersLikeTheApi;

	/** Every global setting an administrator may change, as the config watch compares them */
	private const WATCHED_GLOBALS = [
		'protection_enabled', 'learning_until', 'ban_duration_1', 'ban_duration_2', 'ban_duration_3', 'ban_history_days',
		'ban_net_after', 'ban_shared_ip_users', 'retention_detections_days', 'export_formats', 'blocklist_sources',
		'notify_admin_group', 'notify_admin_email_min_severity', 'admin_change_require_approval', 'digest_frequency',
		'events_include_ip', 'step_up_no_method_flagged_source', 'step_up_no_method_sprayed_password',
		'step_up_no_method_protected_account', 'step_up_no_method_breached_password', 'step_up_no_method_risky_network',
		'step_up_no_method_risk_high', 'step_up_no_method_admin_outside_networks', 'step_up_known_device_ok_for',
		'step_up_admin_approval', 'known_device_enabled', 'risk_enabled', 'risky_network_office_networks',
		'admin_trusted_networks_only', 'risky_network_exempt_groups', 'personal_page_enabled', 'stale_credentials_remove_days',
	];

	/** @var list<array{0: string, 1: mixed, 2: mixed, 3: bool}> */
	private array $events = [];
	private \Closure $listener;

	protected function setUp(): void {
		parent::setUp();
		$this->listener = function (SettingChangedEvent $event): void {
			$this->events[] = [$event->getKey(), $event->getOldValue(), $event->getNewValue(), $event->isReported()];
		};
		Server::get(IEventDispatcher::class)->addListener(SettingChangedEvent::class, $this->listener);
	}

	protected function tearDown(): void {
		Server::get(IEventDispatcher::class)->removeListener(SettingChangedEvent::class, $this->listener);
		Server::get(IUserSession::class)->setUser(null);
		parent::tearDown();
	}

	public function testEveryWriteReportsTheEffectiveValuesBeforeAndAfter(): void {
		$check = CredentialStuffing::ID;
		$defaultResponses = array_map(static fn (ResponseType $r): string => $r->value, $this->checkSettings()->responses($check));

		$this->settingsEditor()->setGlobal(GlobalSettings::BAN_DURATION_1, 7200);
		$this->settingsEditor()->setGlobal(GlobalSettings::BAN_DURATION_1, 7200);
		$this->settingsEditor()->setGlobal(GlobalSettings::EVENTS_INCLUDE_IP, false, reported: false);
		$this->settingsEditor()->setParam($check, 'window', 900);
		$this->settingsEditor()->setParam($check, 'window', 1200, reported: false);
		$this->settingsEditor()->setMode($check, Mode::Observe);
		$this->settingsEditor()->setResponses($check, [ResponseType::NotifyAdmin]);
		$this->settingsEditor()->resetParam($check, 'window');
		$this->settingsEditor()->resetGlobal(GlobalSettings::BAN_DURATION_1);
		$this->settingsEditor()->resetGlobal(GlobalSettings::EVENTS_INCLUDE_IP);
		$this->settingsEditor()->resetCheck($check);

		$this->assertSame([
			['ban_duration_1', 14400, 7200, true],
			['events_include_ip', true, false, false],
			['check_credential_stuffing_window', 600, 900, true],
			['check_credential_stuffing_window', 900, 1200, false],
			['check_credential_stuffing_mode', 'protect', 'observe', true],
			['check_credential_stuffing_responses', $defaultResponses, ['notify_admin'], true],
			['check_credential_stuffing_window', 1200, 600, true],
			['ban_duration_1', 7200, 14400, true],
			['events_include_ip', false, true, true],
			['check_credential_stuffing_mode', 'observe', 'protect', true],
			['check_credential_stuffing_responses', ['notify_admin'], $defaultResponses, true],
		], $this->events);
		$this->assertSame(ProtectionLevel::Custom, $this->settingsEditor()->protectionLevel(), 'a block duration changed by hand');
	}

	public function testSeveralValuesTogetherReportEachChange(): void {
		$changes = $this->settingsEditor()->updateCheck(CredentialStuffing::ID, Mode::Observe, ['window' => 600, 'min_failures' => 25], [ResponseType::NotifyAdmin]);
		$globals = $this->settingsEditor()->updateGlobals([GlobalSettings::BAN_DURATION_1 => 14400, GlobalSettings::BAN_DURATION_2 => 3600, GlobalSettings::DIGEST_FREQUENCY => 'daily']);

		$this->assertSame(['mode' => 'observe', 'params' => ['min_failures' => 25], 'responses' => ['notify_admin']], $changes);
		$this->assertSame([GlobalSettings::BAN_DURATION_2 => 3600, GlobalSettings::DIGEST_FREQUENCY => 'daily'], $globals);
		$this->assertSame([
			['check_credential_stuffing_mode', 'protect', 'observe', true],
			['check_credential_stuffing_min_failures', 10, 25, true],
			['check_credential_stuffing_responses', ['ban', 'flag_source', 'notify_admin'], ['notify_admin'], true],
			['ban_duration_2', 86400, 3600, true],
			['digest_frequency', 'weekly', 'daily', true],
		], $this->events);
		$this->assertSame(ProtectionLevel::Custom, $this->settingsEditor()->protectionLevel(), 'a limit changed by hand');
	}

	public function testAProtectionLevelReportsEachValueButNotTheLevel(): void {
		Server::get(ProtectionLevels::class)->apply(ProtectionLevel::Strict);

		$this->assertContains(['check_credential_stuffing_min_failures', 10, 5, true], $this->events);
		$this->assertContains(['ban_duration_1', 14400, 28800, true], $this->events);
		$this->assertSame([], array_values(array_filter($this->events, static fn (array $e): bool => $e[0] === SettingsEditor::LEVEL_STATE)));
		$this->assertSame(ProtectionLevel::Strict, $this->settingsEditor()->protectionLevel());
	}

	public function testTheLearningPeriodIsReportedOnlyWhenItStartsOrIsExtended(): void {
		$learning = Server::get(LearningService::class);
		$learning->extend(3, 'admin');
		$learning->stop('admin');

		$this->assertCount(2, $this->events);
		$this->assertSame([GlobalSettings::LEARNING_UNTIL, 0], array_slice($this->events[0], 0, 2));
		$this->assertTrue($this->events[0][3], 'starting it is an administration change');
		$this->assertSame(0, $this->events[1][2]);
		$this->assertFalse($this->events[1][3], 'ending it is not');
	}

	public function testRefusedValuesKeepTheirErrorShape(): void {
		$users = Server::get(IUserManager::class);
		if (!$users->userExists('ids_admin')) {
			$users->createUser('ids_admin', 'Ids-Test-Password-2026');
		}
		Server::get(IUserSession::class)->setUser($users->get('ids_admin'));
		$controller = (new Application())->getContainer()->get(AdminApiController::class);

		$tooShort = $this->answer(fn () => $controller->updateSettings([GlobalSettings::BAN_DURATION_1 => 60]));
		$this->assertSame(Http::STATUS_BAD_REQUEST, $tooShort->getStatus());
		$this->assertSame(['message' => '"ban_duration_1" must be at least 300.', 'param' => 'ban_duration_1', 'reason' => 'too_small'], $tooShort->getData());

		$notZero = $this->answer(fn () => $controller->updateSettings([GlobalSettings::STALE_CREDENTIALS_REMOVE_DAYS => 30]));
		$this->assertSame(['message' => '"stale_credentials_remove_days" must be 0 (off) or at least 90.', 'param' => 'stale_credentials_remove_days', 'reason' => 'zero_or_at_least'], $notZero->getData());

		foreach (['installed_at', 'protection_level', 'decoy_count', 'learning_until', 'no_such_setting'] as $name) {
			$unknown = $this->answer(fn () => $controller->updateSettings([$name => 1]));
			$this->assertSame(['message' => 'This check has no setting "' . $name . '".', 'param' => $name, 'reason' => 'unknown_param'], $unknown->getData(), $name);
		}

		$approvers = $this->createMock(Approvers::class);
		$approvers->method('count')->willReturn(1);
		$this->overwriteService(Approvers::class, $approvers);
		try {
			$refused = $this->answer(fn () => $controller->updateSettings([GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL => true]));
		} finally {
			$this->restoreService(Approvers::class);
		}
		$this->assertSame('too_few_admins', $refused->getData()['reason']);
		$this->assertSame(GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL, $refused->getData()['param']);

		$check = $this->answer(fn () => $controller->updateCheck(CredentialStuffing::ID, null, null, ['min_failures' => 1]));
		$this->assertSame(['message' => '"min_failures" must be at least 3.', 'param' => 'min_failures', 'reason' => 'too_small'], $check->getData());
		$this->assertSame([], $this->events, 'nothing refused was saved');
	}

	public function testTheConfigWatchComparesEveryOwnSetting(): void {
		$own = [];
		foreach (array_keys(Server::get(WatchedSettings::class)->read()) as $key) {
			$name = WatchedSettings::ownName($key);
			if ($name !== null) {
				$own[] = $name;
			}
		}
		$expected = self::WATCHED_GLOBALS;
		foreach (Server::get(CheckRegistry::class)->all() as $check) {
			$expected[] = Keys::mode($check->id);
			$expected[] = Keys::responses($check->id);
			foreach ($check->params as $param) {
				$expected[] = Keys::param($check->id, $param->name);
			}
		}
		$this->assertEqualsCanonicalizing($expected, $own);
	}
}
