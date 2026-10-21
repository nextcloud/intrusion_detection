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
use OCA\IntrusionDetection\Migration\Version1000Date20261022100000;
use OCA\IntrusionDetection\Repair\RemoveRetiredSettings;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\IOutput;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

#[Group('DB')]
class RetentionMergeMigrationTest extends IntegrationTestCase {
	/** @var list<string> */
	private array $logged = [];

	public function testAnUnsetHistoryPeriodCountsAsNinetyDays(): void {
		$this->settings()->setGlobal(GlobalSettings::RETENTION_DETECTIONS_DAYS, 180);
		$this->migrate();
		$this->assertSame(90, $this->settings()->getInt(GlobalSettings::RETENTION_DETECTIONS_DAYS));
		$this->assertSame(['Intrusion detection: Keep records for is now 90 days: the login history was kept 90 days, and the shorter period wins.'], $this->logged);
	}

	public function testAShorterHistoryPeriodWins(): void {
		$this->appConfig->setValueMixed(Application::APP_ID, RemoveRetiredSettings::HISTORY_RETENTION_DAYS, '30');
		$this->migrate();
		$this->assertSame(30, $this->settings()->getInt(GlobalSettings::RETENTION_DETECTIONS_DAYS));
		$this->assertCount(1, $this->logged);
	}

	public function testAShorterDetectionPeriodStays(): void {
		$this->settings()->setGlobal(GlobalSettings::RETENTION_DETECTIONS_DAYS, 60);
		$this->appConfig->setValueMixed(Application::APP_ID, RemoveRetiredSettings::HISTORY_RETENTION_DAYS, '180');
		$this->migrate();
		$this->assertSame(60, $this->settings()->getInt(GlobalSettings::RETENTION_DETECTIONS_DAYS));
		$this->assertSame(['Intrusion detection: Keep records for stays 60 days, now also for the login history, which was kept 180 days: the shorter period wins.'], $this->logged);
	}

	public function testEqualPeriodsChangeNothing(): void {
		$this->migrate();
		$this->assertSame(90, $this->settings()->getInt(GlobalSettings::RETENTION_DETECTIONS_DAYS));
		$this->assertSame([], $this->logged);
	}

	public function testASecondRunChangesNothing(): void {
		$this->settings()->setGlobal(GlobalSettings::RETENTION_DETECTIONS_DAYS, 180);
		$this->migrate();
		$this->repair();
		$this->logged = [];
		$this->migrate();
		$this->assertSame(90, $this->settings()->getInt(GlobalSettings::RETENTION_DETECTIONS_DAYS));
		$this->assertSame([], $this->logged);
	}

	public function testAPeriodSetLaterIsKeptByTheRepairStep(): void {
		$this->settings()->setGlobal(GlobalSettings::RETENTION_DETECTIONS_DAYS, 180);
		$this->appConfig->setValueMixed(Application::APP_ID, RemoveRetiredSettings::HISTORY_RETENTION_DAYS, '90');
		$this->migrate();
		$this->repair();
		$this->assertSame(90, $this->settings()->getInt(GlobalSettings::RETENTION_DETECTIONS_DAYS));

		$this->settings()->setGlobal(GlobalSettings::RETENTION_DETECTIONS_DAYS, 180);
		$this->repair();
		$this->repair();
		$this->assertSame(180, $this->settings()->getInt(GlobalSettings::RETENTION_DETECTIONS_DAYS), 'Only the migration merges, and it runs once');
	}

	private function migrate(): void {
		$migration = new Version1000Date20261022100000($this->appConfig, Server::get(GlobalSettings::class), $this->settings(), $this->logger());
		$migration->postSchemaChange($this->createMock(IOutput::class), fn (): ISchemaWrapper => $this->createMock(ISchemaWrapper::class), []);
	}

	private function repair(): void {
		(new RemoveRetiredSettings($this->appConfig, $this->logger()))->run($this->createMock(IOutput::class));
	}

	private function logger(): LoggerInterface {
		$logger = $this->createMock(LoggerInterface::class);
		$logger->method('info')->willReturnCallback(function (string $message): void {
			$this->logged[] = $message;
		});
		return $logger;
	}

	private function settings(): Settings {
		return Server::get(Settings::class);
	}
}
