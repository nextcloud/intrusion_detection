<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\AdminChange;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\WatchedSettings;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChangeDetector;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Signal\AdminChanged;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class AdminChangeDetectorTest extends TestCase {
	private const NOW = 1_800_000_000;

	/**
	 * @return array<string, array{string, mixed, mixed, Severity}>
	 */
	public static function settingChanges(): array {
		$own = static fn (string $name): string => WatchedSettings::ownKey($name);
		return [
			'trusted proxies' => [WatchedSettings::systemKey('trusted_proxies'), ['10.0.0.1'], ['10.0.0.1', '10.0.0.2'], Severity::High],
			'brute-force allowlist' => [WatchedSettings::BRUTEFORCE_ALLOWLIST, [], ['0.0.0.0/0'], Severity::High],
			'2FA enforcement off' => [WatchedSettings::systemKey('twofactor_enforced'), 'true', 'false', Severity::High],
			'2FA enforcement removed' => [WatchedSettings::systemKey('twofactor_enforced'), 'true', null, Severity::High],
			'2FA enforcement on' => [WatchedSettings::systemKey('twofactor_enforced'), 'false', 'true', Severity::Low],
			'2FA groups' => [WatchedSettings::systemKey('twofactor_enforced_groups'), [], ['staff'], Severity::Low],
			'trusted domains' => [WatchedSettings::systemKey('trusted_domains'), ['a'], ['a', 'b'], Severity::Low],
			'link sharing' => [WatchedSettings::appKey('core', 'shareapi_allow_links'), 'no', 'yes', Severity::Low],
			'this app off' => [$own(GlobalSettings::ENABLED), true, false, Severity::High],
			'this app on' => [$own(GlobalSettings::ENABLED), false, true, Severity::Low],
			'check to observe' => [$own(Keys::mode('credential_stuffing')), 'protect', 'observe', Severity::High],
			'check to off' => [$own(Keys::mode('credential_stuffing')), 'observe', 'off', Severity::High],
			'check to protect' => [$own(Keys::mode('credential_stuffing')), 'off', 'protect', Severity::Low],
			'learning started' => [$own(GlobalSettings::LEARNING_UNTIL), 0, self::NOW + 86400, Severity::High],
			'learning started again after it ran out' => [$own(GlobalSettings::LEARNING_UNTIL), self::NOW - 60, self::NOW + 86400, Severity::High],
			'learning extended' => [$own(GlobalSettings::LEARNING_UNTIL), self::NOW + 3600, self::NOW + 86400, Severity::Medium],
			'learning shortened' => [$own(GlobalSettings::LEARNING_UNTIL), self::NOW + 86400, self::NOW + 3600, Severity::Low],
			'learning ended' => [$own(GlobalSettings::LEARNING_UNTIL), self::NOW + 3600, 0, Severity::Low],
			'approval off' => [$own(GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL), true, false, Severity::High],
			'approval on' => [$own(GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL), false, true, Severity::Low],
			'a threshold' => [$own(Keys::param('credential_stuffing', 'window')), 600, 900, Severity::Low],
			'secret trusted proxies' => [WatchedSettings::systemKey('trusted_proxies'), null, null, Severity::High],
			'secret other' => [WatchedSettings::systemKey('intrusion_detection.token'), null, null, Severity::Low],
		];
	}

	#[DataProvider('settingChanges')]
	public function testSettingSeverity(string $key, mixed $old, mixed $new, Severity $expected): void {
		$this->assertSame($expected, AdminChangeDetector::settingSeverity($key, $old, $new, self::NOW));
	}

	public function testSettingsOfThisAppAndThePasswordPolicyShareANotification(): void {
		$this->assertSame('setting:app:intrusion_detection', AdminChangeDetector::settingAlertKey(WatchedSettings::ownKey('check_trap_url_mode')));
		$this->assertSame('setting:app:intrusion_detection', AdminChangeDetector::settingAlertKey(WatchedSettings::ownKey('ban_net_after')));
		$this->assertSame('setting:app:password_policy', AdminChangeDetector::settingAlertKey(WatchedSettings::appKey('password_policy', 'minLength')));
		$this->assertSame('setting:system:trusted_domains', AdminChangeDetector::settingAlertKey(WatchedSettings::systemKey('trusted_domains')));
		$this->assertSame('setting:' . WatchedSettings::BRUTEFORCE_ALLOWLIST, AdminChangeDetector::settingAlertKey(WatchedSettings::BRUTEFORCE_ALLOWLIST));
	}

	public function testAChangeCarriesKindActorSubjectAddressAndAlertKey(): void {
		$mode = new ModeState(Mode::Protect, Mode::Protect);
		[$draft] = $this->drafts(new AdminChanged(AdminChange::KIND_ADMIN_GRANTED, Severity::High, 'alice', 'bob', ['group' => 'admin'], 'admin_granted:admin'), false, $mode);
		$this->assertSame(AdminChange::ID, $draft->checkId);
		$this->assertSame('bob', $draft->uid);
		$this->assertSame(Severity::High, $draft->severity);
		$this->assertNull($draft->source, 'The actor\'s address is a fact, not the detection\'s source');
		$this->assertSame(AdminChange::KIND_ADMIN_GRANTED, $draft->facts['kind']);
		$this->assertSame('alice', $draft->facts['actor']);
		$this->assertSame(['bob'], $draft->facts['targets']);
		$this->assertSame('198.51.100.7', $draft->facts['actor_ip']);
		$this->assertSame('admin_granted:admin', $draft->facts[AdminAlerts::FACT_ALERT_KEY]);
		$this->assertTrue($draft->facts[AdminAlerts::FACT_ALL_ADMINS]);
		$this->assertSame(DetectionDraft::MERGE_NONE, $draft->merge, 'One detection per change');
		$this->assertSame($mode, $draft->mode, 'Recorded in the mode it was judged by');
	}

	public function testOnTheCommandLineNoAddressIsRecorded(): void {
		[$draft] = $this->drafts(new AdminChanged(AdminChange::KIND_APP_ENABLED, Severity::Medium, ActorResolver::OCC, null, ['app' => 'files'], 'app_enabled'), true);
		$this->assertArrayNotHasKey('actor_ip', $draft->facts);
	}

	public function testSecretSettingsCarryNoValues(): void {
		[$draft] = $this->drafts(AdminChangeDetector::settingChange(WatchedSettings::systemKey('intrusion_detection.token'), 'old-s3cr3t', 'new-s3cr3t', true, ActorResolver::UNKNOWN, true, self::NOW), false);
		$this->assertTrue($draft->facts['secret']);
		$this->assertArrayNotHasKey('old', $draft->facts);
		$this->assertArrayNotHasKey('new', $draft->facts);
		$this->assertStringNotContainsString('s3cr3t', json_encode($draft->facts, JSON_THROW_ON_ERROR));
	}

	public function testWatchFindingsHaveNoAddress(): void {
		[$draft] = $this->drafts(AdminChangeDetector::settingChange(WatchedSettings::systemKey('overwritehost'), 'a', 'b', false, ActorResolver::UNKNOWN, true, self::NOW), false);
		$this->assertArrayNotHasKey('actor_ip', $draft->facts);
		$this->assertTrue($draft->facts['watch']);
		$this->assertSame('a', $draft->facts['old']);
		$this->assertSame('b', $draft->facts['new']);
	}

	/**
	 * @return list<DetectionDraft>
	 */
	private function drafts(AdminChanged $change, bool $commandLine, ?ModeState $mode = null): array {
		$actors = $this->createMock(ActorResolver::class);
		$actors->method('isCommandLine')->willReturn($commandLine);
		$addresses = $this->createMock(RemoteAddressResolver::class);
		$addresses->method('current')->willReturn(SourceKey::fromIp('198.51.100.7'));
		$drafts = (new AdminChangeDetector($actors, $addresses))->detect($change, $mode ?? new ModeState(Mode::Protect, Mode::Protect));
		$this->assertIsArray($drafts);
		$this->assertCount(1, $drafts);
		return $drafts;
	}
}
