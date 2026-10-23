<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\PurgeRetention;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Detections are the app's own record of what happened. A shorter
 * retention applies only after PurgeRetention::DELAY, so lowering it
 * cannot delete the evidence before anyone read the alert about it.
 */
#[Group('DB')]
class RetentionDelayTest extends IntegrationTestCase {
	private const DAY = 86400;

	public function testALoweredRetentionWaitsBeforeAnythingIsDeleted(): void {
		$now = time();
		$this->detectionAt($now - 30 * self::DAY);
		$totals = Server::get(DetectionTotals::class);
		$this->assertSame(0, $totals->purge($now));

		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::RETENTION_DETECTIONS_DAYS, 7);
		$this->assertSame(0, $totals->purge($now + 300), 'Lowered just now: nothing older goes yet');
		$this->assertSame(0, $totals->purge($now + PurgeRetention::DELAY - 300));
		$this->assertSame(1, $totals->purge($now + PurgeRetention::DELAY + 300), 'After the delay the shorter retention applies');
	}

	public function testALongerRetentionAppliesAtOnce(): void {
		$now = time();
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::RETENTION_DETECTIONS_DAYS, 30);
		$retention = Server::get(PurgeRetention::class);
		$this->assertSame(30, $retention->days($now));
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::RETENTION_DETECTIONS_DAYS, 60);
		$this->assertSame(60, $retention->days($now + 60));
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::RETENTION_DETECTIONS_DAYS, 10);
		$this->assertSame(60, $retention->days($now + 120));
	}

	public function testTheLoginHistoryAndTheSecurityChangesWaitToo(): void {
		$now = time();
		$retention = Server::get(PurgeRetention::class);
		$this->assertSame(90, $retention->days($now));
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::RETENTION_DETECTIONS_DAYS, 7);
		foreach ([LoginHistory::class, SecurityChangeLog::class] as $owner) {
			Server::get($owner)->purge($now + 60);
		}
		$this->assertSame(90, $retention->days($now + 60));
	}

	private function detectionAt(int $at): void {
		$qb = $this->db->getQueryBuilder();
		$qb->insert('ids_detections')->values([
			'check_id' => $qb->createNamedParameter('trap_url'),
			'severity' => $qb->createNamedParameter('low'),
			'created_at' => $qb->createNamedParameter($at),
			'last_seen_at' => $qb->createNamedParameter($at),
		])->executeStatement();
	}
}
