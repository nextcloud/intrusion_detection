<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Repair\RemoveRetiredSettings;
use OCP\Migration\IOutput;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

#[Group('DB')]
class RemoveRetiredSettingsTest extends IntegrationTestCase {
	/** @var list<string> */
	private array $logged = [];

	public function testEveryRetiredValueIsDeletedAndOnlyChangedOnesAreLogged(): void {
		$this->appConfig->setValueMixed(Application::APP_ID, 'step_up_code_ttl', '300');
		$this->appConfig->setValueMixed(Application::APP_ID, 'risk_points_tor', '2');
		$this->appConfig->setValueMixed(Application::APP_ID, 'risk_factor_high', '0.1');
		$this->appConfig->setValueMixed(Application::APP_ID, 'risk_attack_tool_patterns', '["evilscan"]');
		$this->appConfig->setValueMixed(Application::APP_ID, 'digest_send_quiet', 'false');
		$this->appConfig->setValueMixed(Application::APP_ID, 'learning_decoys_act', '1');
		$this->appConfig->setValueMixed(Application::APP_ID, 'blocklist_max_entries', '200000');

		$this->repair();

		$this->assertSame([], array_intersect($this->appConfig->getKeys(Application::APP_ID), array_keys(RemoveRetiredSettings::retired())));
		$this->assertCount(4, $this->logged);
		$this->assertStringContainsString('"step_up_code_ttl" is no longer a setting. It was 300; now: 600 seconds.', implode("\n", $this->logged));
		$this->assertStringContainsString('"risk_factor_high" is no longer a setting. It was 0.1; now: 0.25.', implode("\n", $this->logged));
		$this->assertStringContainsString('It was ["evilscan"]; now: the built-in list of attack tools only.', implode("\n", $this->logged));
		$this->assertStringContainsString('"digest_send_quiet" is no longer a setting. It was false; now: quiet digests are always sent.', implode("\n", $this->logged));
	}

	public function testTheOldHistoryPeriodIsOnlyDeleted(): void {
		$this->settings()->setGlobal(GlobalSettings::RETENTION_DETECTIONS_DAYS, 180);
		$this->appConfig->setValueMixed(Application::APP_ID, RemoveRetiredSettings::HISTORY_RETENTION_DAYS, '30');
		$this->repair();
		$this->assertNotContains(RemoveRetiredSettings::HISTORY_RETENTION_DAYS, $this->appConfig->getKeys(Application::APP_ID));
		$this->assertSame(180, $this->settings()->getInt(GlobalSettings::RETENTION_DETECTIONS_DAYS), 'The migration merges the periods, once');
		$this->assertSame([], $this->logged);
	}

	public function testRetiredInternalValuesAreOnlyDeleted(): void {
		$this->appConfig->setValueMixed(Application::APP_ID, 'cs_evaluated_at', (string)time());
		$this->repair();
		$this->assertNotContains('cs_evaluated_at', $this->appConfig->getKeys(Application::APP_ID));
		$this->assertSame([], $this->logged);
	}

	public function testItIsIdempotent(): void {
		$this->appConfig->setValueMixed(Application::APP_ID, 'flag_duration', '3600');
		$this->repair();
		$this->assertCount(1, $this->logged);

		$this->logged = [];
		$this->repair();
		$this->assertSame([], $this->logged);
		$this->assertNotContains('flag_duration', $this->appConfig->getKeys(Application::APP_ID));
	}

	private function repair(): void {
		$logger = $this->createMock(LoggerInterface::class);
		$logger->method('info')->willReturnCallback(function (string $message): void {
			$this->logged[] = $message;
		});
		$step = new RemoveRetiredSettings($this->appConfig, $logger);
		$step->run($this->createMock(IOutput::class));
	}

	private function settings(): Settings {
		return Server::get(Settings::class);
	}
}
