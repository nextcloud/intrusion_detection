<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\AdminChange;

use OCA\IntrusionDetection\Admin\GlobalSettingsPresenter;
use OCA\IntrusionDetection\AdminChange\WatchedSettings;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

/**
 * The names the admin feed and the alerts show for changed settings: never
 * a raw config key for a setting of this app.
 */
class WatchedSettingsLabelTest extends TestCase {
	private IL10N $l;
	private WatchedSettings $watched;

	protected function setUp(): void {
		parent::setUp();
		$this->l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$this->watched = Server::get(WatchedSettings::class);
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function modeKeys(): array {
		return [
			'watched key' => ['app:intrusion_detection:check_credential_stuffing_mode'],
			'without the app: prefix' => ['intrusion_detection:check_credential_stuffing_mode'],
		];
	}

	#[DataProvider('modeKeys')]
	public function testTheModeOfACheckIsNamedByTheCheck(string $key): void {
		$name = Server::get(CheckRegistry::class)->get('credential_stuffing')->texts($this->l)->name;
		$this->assertSame('Intrusion detection: mode of "' . $name . '"', $this->watched->label($key, $this->l));
	}

	public function testAGlobalSettingUsesTheLabelOfTheSettingsTab(): void {
		$label = Server::get(GlobalSettingsPresenter::class)->label(GlobalSettings::BAN_DURATION_1, $this->l);
		$this->assertNotNull($label);
		$this->assertSame('Intrusion detection: ' . $label, $this->watched->label('intrusion_detection:' . GlobalSettings::BAN_DURATION_1, $this->l));
	}

	public function testOtherAppsNameTheAppAndTheKey(): void {
		$this->assertSame('Setting foo of the app files', $this->watched->label('files:foo', $this->l));
		$this->assertSame('debug in config.php', $this->watched->label('system:debug', $this->l));
	}
}
