<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\SystemConfig;
use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\ConfigWatch;
use OCA\IntrusionDetection\AdminChange\DisplayValue;
use OCA\IntrusionDetection\AdminChange\WatchedSettings;
use OCA\IntrusionDetection\AdminChange\WatchedValue;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\ConfigSnapshotMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\State\AppState;
use OCP\App\IAppManager;
use OCP\IAppConfig;
use OCP\IConfig;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * The config watch (concept section 10.15): a baseline first, then one
 * detection per changed setting, and secrets never shown or stored.
 */
#[Group('DB')]
class ConfigWatchTest extends AdminChangeTestCase {
	private const SECRET = 'Config-Secret-Value-5e5e';
	private const SECRET_2 = 'Config-Secret-Value-6f6f';

	/** @var array<string, mixed> config.php as the watch sees it */
	private array $system = [];
	/** @var array<string, true> config.php keys Nextcloud treats as secret */
	private array $sensitive = [];
	private ConfigWatch $watch;
	private SystemConfig $systemConfig;

	protected function setUp(): void {
		parent::setUp();
		$this->act(ActorResolver::CRON, true);
		$this->system = [
			'trusted_proxies' => ['10.0.0.1'],
			'trusted_domains' => ['cloud.example.com'],
			'loglevel' => 2,
			'secret' => 'not-watched',
		];
		// As in core: the proxies are hidden from support reports, so they count as secret.
		$this->sensitive = ['trusted_proxies' => true];
		$systemConfig = $this->createMock(SystemConfig::class);
		$systemConfig->method('getKeys')->willReturnCallback(fn (): array => array_keys($this->system));
		$systemConfig->method('getValue')->willReturnCallback(fn (string $key, mixed $default = ''): mixed => $this->system[$key] ?? $default);
		$systemConfig->method('getFilteredValue')->willReturnCallback(fn (string $key, mixed $default = ''): mixed => isset($this->sensitive[$key]) ? IConfig::SENSITIVE_VALUE : ($this->system[$key] ?? $default));
		$this->systemConfig = $systemConfig;
		$this->watch = $this->configWatch($this->watchedSettings());
	}

	private function watchedSettings(): WatchedSettings {
		return new WatchedSettings($this->systemConfig, Server::get(IAppConfig::class), $this->appSettings(), $this->checkSettings(), Server::get(CheckRegistry::class), new GlobalSettings(), Server::get(LoggerInterface::class));
	}

	protected function tearDown(): void {
		$appConfig = Server::get(IAppConfig::class);
		$appConfig->deleteKey('bruteForce', 'whitelist_ids_test');
		$appConfig->deleteKey('password_policy', 'idsTestMinLength');
		parent::tearDown();
	}

	public function testTheFirstRunOnlyRecordsTheBaseline(): void {
		$this->assertSame(0, $this->watch->run());
		$this->assertSame([], $this->adminChanges());
		$this->assertGreaterThan(0, Server::get(AppState::class)->getInt(ConfigWatch::BASELINE_STATE));
		$snapshot = $this->snapshot();
		$this->assertSame('["cloud.example.com"]', $snapshot[WatchedSettings::systemKey('trusted_domains')]['display_value']);
		$this->assertNull($snapshot[WatchedSettings::systemKey('trusted_proxies')]['display_value']);
		$this->assertArrayHasKey(WatchedSettings::systemKey('overwritehost'), $snapshot, 'Fixed keys are watched even when not set');
		$this->assertArrayNotHasKey(WatchedSettings::systemKey('secret'), $snapshot, 'Only the watched keys');
		$this->assertArrayHasKey(WatchedSettings::ownKey(Keys::mode('credential_stuffing')), $snapshot);
		$this->assertArrayNotHasKey(WatchedSettings::ownKey(AppState::INSTALLED_AT), $snapshot, 'Internal state is not watched');
	}

	public function testAChangeIsOneDetectionAndOnlyOnce(): void {
		$this->watch->run();
		$this->system['trusted_proxies'] = ['10.0.0.1', '203.0.113.9'];
		$this->system['trusted_domains'] = ['cloud.example.com', 'evil.example.net'];
		$this->system['loglevel'] = 0;
		$this->assertSame(3, $this->watch->run());
		$this->assertSame(0, $this->watch->run(), 'Nothing changed since');

		$changes = $this->adminChanges();
		$this->assertCount(3, $changes);
		$byKey = [];
		foreach ($changes as $detection) {
			$byKey[$this->facts($detection)['setting']] = $detection;
		}
		$proxies = $byKey[WatchedSettings::systemKey('trusted_proxies')];
		$this->assertSame(Severity::High->value, $proxies->getSeverity());
		$this->assertTrue($this->facts($proxies)['secret'], 'Core treats the proxies as secret');
		$this->assertArrayNotHasKey('new', $this->facts($proxies));

		$domains = $byKey[WatchedSettings::systemKey('trusted_domains')];
		$facts = $this->facts($domains);
		$this->assertSame(Severity::Low->value, $domains->getSeverity());
		$this->assertSame(['cloud.example.com'], $facts['old']);
		$this->assertSame(['cloud.example.com', 'evil.example.net'], $facts['new']);
		$this->assertTrue($facts['watch']);
		$this->assertSame(ActorResolver::UNKNOWN, $facts['actor']);
		$this->assertSame(Severity::Low->value, $byKey[WatchedSettings::systemKey('loglevel')]->getSeverity());

		$narrative = implode(' ', Server::get(NarrativeBuilder::class)->build($domains, $this->l())->happened);
		$this->assertStringContainsString('"trusted_domains in config.php" changed from "cloud.example.com" to "cloud.example.com, evil.example.net"', $narrative);
		$this->assertStringContainsString('Nextcloud cannot tell who made this change', $narrative);
	}

	public function testNewAndRemovedSettingsAreChanges(): void {
		$this->watch->run();
		$this->system['overwrite.cli.url'] = 'https://cloud.example.com';
		$this->system['overwriteexotic'] = 'x';
		$this->assertSame(2, $this->watch->run());
		unset($this->system['overwriteexotic']);
		$this->assertSame(1, $this->watch->run());
		$last = $this->adminChanges()[2];
		$this->assertSame('x', $this->facts($last)['old']);
		$this->assertNull($this->facts($last)['new']);
	}

	/**
	 * On devel an update that removed 17 settings of this app raised 17
	 * alerts "changed from … to not set" with an unknown actor.
	 */
	public function testSettingsAnUpdateRemovedRaiseNoAlerts(): void {
		$this->watch->run();
		$snapshots = Server::get(ConfigSnapshotMapper::class);
		$fingerprinter = Server::get(Fingerprinter::class);
		$removed = [];
		foreach (['sensitive_actions_enabled', 'sensitive_window', 'lockdown_enabled', 'lockdown_until', 'lockdown_reason', 'check_sensitive_action_mode', 'check_sensitive_action_responses', 'check_lockdown_mode'] as $name) {
			$removed[] = WatchedSettings::ownKey($name);
		}
		for ($i = count($removed); $i < 17; $i++) {
			$removed[] = WatchedSettings::ownKey('check_sensitive_action_param_' . $i);
		}
		foreach ($removed as $key) {
			$snapshots->store($key, $fingerprinter->setting(WatchedValue::canonicalOf(true)), DisplayValue::encode(true), time());
		}

		$this->assertSame(0, $this->watch->run());
		$this->assertSame([], $this->adminChanges());
		$this->assertSame([], array_intersect($removed, array_keys($this->snapshot())), 'Their rows are gone');
		$this->assertSame(0, $this->watch->run());
	}

	public function testOwnSettingsAreComparedByTheirStoredValue(): void {
		$this->watch->run();
		// Stored explicitly with the value it had by default: nothing changed.
		$this->appConfig->setValueInt(Application::APP_ID, Keys::param('credential_stuffing', 'window'), 600);
		$this->assertSame(0, $this->watch->run());
		$this->appConfig->setValueInt(Application::APP_ID, Keys::param('credential_stuffing', 'window'), 900);
		$this->assertSame(1, $this->watch->run());
	}

	public function testAfterAnUpdateTheAppsSettingsAreRecordedAgainSilently(): void {
		$version = '1.0.1';
		$appManager = $this->createMock(IAppManager::class);
		$appManager->method('getAppVersion')->willReturnCallback(static function () use (&$version): string {
			return $version;
		});
		$watch = $this->configWatch($this->watchedSettings(), null, $appManager);
		$watch->run();

		// The update changed what is stored, for example by renaming a setting.
		$version = '1.0.2';
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode('credential_stuffing'), Mode::Observe->value);
		$this->system['loglevel'] = 0;
		$this->assertSame(1, $watch->run(), 'Only the change outside this app is reported');
		$this->assertSame(WatchedSettings::systemKey('loglevel'), $this->facts($this->adminChanges()[0])['setting']);

		$this->appConfig->setValueString(Application::APP_ID, Keys::mode('credential_stuffing'), Mode::Off->value);
		$this->assertSame(1, $watch->run(), 'Without an update, changes of this app are reported again');
	}

	public function testAppConfigIsWatched(): void {
		$this->watch->run();
		$appConfig = Server::get(IAppConfig::class);
		$appConfig->setValueString('bruteForce', 'whitelist_ids_test', '0.0.0.0/0');
		$appConfig->setValueString('password_policy', 'idsTestMinLength', '4');
		$this->assertSame(2, $this->watch->run());
		$byKey = [];
		foreach ($this->adminChanges() as $detection) {
			$byKey[$this->facts($detection)['setting']] = $detection;
		}
		$this->assertSame(Severity::High->value, $byKey[WatchedSettings::BRUTEFORCE_ALLOWLIST]->getSeverity());
		$this->assertSame(['0.0.0.0/0'], $this->facts($byKey[WatchedSettings::BRUTEFORCE_ALLOWLIST])['new']);
		$this->assertArrayHasKey(WatchedSettings::appKey('password_policy', 'idsTestMinLength'), $byKey);
	}

	public function testOwnSettingsChangedAroundTheAppAreFound(): void {
		$this->watch->run();
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode('credential_stuffing'), Mode::Off->value);
		$this->assertSame(1, $this->watch->run());
		[$detection] = $this->adminChanges();
		$this->assertSame(Severity::High->value, $detection->getSeverity());
		$this->assertSame('Security setting changed: Intrusion detection: mode of "Credential stuffing"', Server::get(AdminAlerts::class)->headline($detection, $this->l()));
	}

	public function testOwnSettingsAreNamedAsOnTheAdminPage(): void {
		$watched = Server::get(WatchedSettings::class);
		$this->assertSame('Intrusion detection: "Different accounts" of "Credential stuffing"', $watched->label(WatchedSettings::ownKey(Keys::param('credential_stuffing', 'min_names')), $this->l()));
		$this->assertSame('Intrusion detection: First block', $watched->label(WatchedSettings::ownKey(GlobalSettings::BAN_DURATION_1), $this->l()));
		$this->assertSame('Intrusion detection: not_a_setting', $watched->label(WatchedSettings::ownKey('not_a_setting'), $this->l()));
	}

	public function testOwnSettingsChangedThroughTheAppAreNotReportedTwice(): void {
		Server::get(ConfigWatch::class)->run();
		$this->assertSame([], $this->adminChanges());
		$this->settingsEditor()->setParam('credential_stuffing', 'min_names', 7);
		$this->assertCount(1, $this->adminChanges(), 'Reported by the app at once');
		$this->assertSame(0, Server::get(ConfigWatch::class)->run(), 'The watch has nothing left to report');
	}

	public function testSecretsAreNeverShownOrStored(): void {
		$this->system['intrusion_detection.token'] = self::SECRET;
		$this->sensitive['intrusion_detection.token'] = true;
		$this->watch->run();
		$this->system['intrusion_detection.token'] = self::SECRET_2;
		$this->assertSame(1, $this->watch->run());

		[$detection] = $this->adminChanges();
		$facts = $this->facts($detection);
		$this->assertTrue($facts['secret']);
		$this->assertArrayNotHasKey('old', $facts);
		$this->assertArrayNotHasKey('new', $facts);
		$this->assertNull($this->snapshot()[WatchedSettings::systemKey('intrusion_detection.token')]['display_value']);
		$hash = $this->snapshot()[WatchedSettings::systemKey('intrusion_detection.token')]['value_hash'];
		$this->assertNotSame(hash('sha256', serialize(self::SECRET_2)), $hash, 'The hash is keyed');

		$texts = json_encode($this->allRows('ids_detections')) . json_encode($this->allRows('ids_config_snapshot')) . json_encode($this->allRows('ids_alerts'));
		$texts .= implode(' ', Server::get(NarrativeBuilder::class)->build($detection, $this->l())->happened);
		foreach ($this->notificationsWithSubject(AdminAlerts::SUBJECT) as $notification) {
			$prepared = Server::get(Notifier::class)->prepare($notification, 'en');
			$texts .= $prepared->getParsedSubject() . $prepared->getParsedMessage() . json_encode($notification->getSubjectParameters());
		}
		$admin = $this->user($this->alice);
		$texts .= json_encode(get_object_vars(Server::get(AdminAlerts::class)->mailFor($detection, $admin)));
		$this->assertNotSame('', $texts);
		foreach ([self::SECRET, self::SECRET_2] as $secret) {
			$this->assertStringNotContainsString($secret, $texts);
		}
		$this->assertStringContainsString('Its value is secret', $texts);
	}

	public function testSwitchingTheCheckOffStartsANewBaseline(): void {
		$this->watch->run();
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode(AdminChange::ID), Mode::Off->value);
		$this->assertSame(0, $this->watch->run());
		$this->assertSame(0, Server::get(AppState::class)->getInt(ConfigWatch::BASELINE_STATE));

		$this->system['trusted_proxies'] = [];
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode(AdminChange::ID), Mode::Protect->value);
		$this->assertSame(0, $this->watch->run(), 'Changes while it was off are not told: nobody knows when they happened');
		$this->assertSame([], $this->adminChanges());
	}

	public function testANewlyWatchedFixedKeyIsRecordedSilently(): void {
		$this->watch->run();
		$qb = $this->db->getQueryBuilder();
		$qb->delete('ids_config_snapshot')->where($qb->expr()->eq('setting_key', $qb->createNamedParameter(WatchedSettings::systemKey('debug'))))->executeStatement();
		$this->assertSame(0, $this->watch->run());
		$this->assertArrayHasKey(WatchedSettings::systemKey('debug'), $this->snapshot());
	}

	/**
	 * @return array<string, array<string, mixed>>
	 */
	private function snapshot(): array {
		$rows = [];
		foreach ($this->allRows('ids_config_snapshot') as $row) {
			$rows[(string)$row['setting_key']] = $row;
		}
		return $rows;
	}

	/**
	 * @return list<array<string, mixed>>
	 */
	private function allRows(string $table): array {
		$result = $this->db->getQueryBuilder()->select('*')->from($table)->executeQuery();
		$rows = $result->fetchAll();
		$result->closeCursor();
		return $rows;
	}

	private function l(): \OCP\IL10N {
		return Server::get(IFactory::class)->get(Application::APP_ID, 'en');
	}
}
