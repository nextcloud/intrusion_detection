<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\Checks\DecoyCredential;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The running totals behind the statistics and the detections metric.
 */
#[Group('DB')]
class DetectionTotalsTest extends IntegrationTestCase {
	public function testARaisedSeverityAddsToTheNewSeverityAndTakesNothingFromTheOld(): void {
		$service = Server::get(DetectionService::class);
		$totals = Server::get(DetectionTotals::class);
		$protect = new ModeState(Mode::Protect, Mode::Protect);
		$draft = fn (?Severity $severity): DetectionDraft => new DetectionDraft(DecoyCredential::ID, SourceKey::fromIp('203.0.113.20'), null, [], merge: DetectionDraft::MERGE_SOURCE, severity: $severity);

		[$detection] = $service->record($draft(Severity::Medium), $protect);
		$this->assertSame([['check' => DecoyCredential::ID, 'severity' => 'medium', 'enforced' => true, 'count' => 1]], $totals->totals());

		$service->record($draft(Severity::Critical), $protect);
		$service->record($draft(Severity::Critical), $protect);
		$this->assertSame('critical', Server::get(DetectionMapper::class)->findById($detection->getId())->getSeverity());
		$this->assertSame([
			['check' => DecoyCredential::ID, 'severity' => 'critical', 'enforced' => true, 'count' => 1],
			['check' => DecoyCredential::ID, 'severity' => 'medium', 'enforced' => true, 'count' => 1],
		], $totals->totals(), 'the medium series does not go down; a merge without a raise adds nothing');

		$this->assertCount(1, $totals->perDay(time() - 86400, 0), 'the chart counts the detection once');
		$this->assertSame(1, $totals->perDay(time() - 86400, 0)[0]['count']);
	}

	public function testTheTotalsReadOnlyTheHourlyTable(): void {
		for ($i = 0; $i < 20; $i++) {
			$this->insert('trap_url', 'low', false, time() - $i * 3600);
		}
		$queries = $this->db->getInner()->getStats()['executed'];
		$this->assertSame(20, Server::get(DetectionTotals::class)->totals()[0]['count']);
		$this->assertLessThanOrEqual(1, $this->db->getInner()->getStats()['executed'] - $queries);
	}

	public function testOldHoursAreFoldedIntoTheRunningTotal(): void {
		$this->insert('trap_url', 'low', false, time() - 200 * 86400);
		$this->insert('trap_url', 'low', false, time());
		$totals = Server::get(DetectionTotals::class);
		$this->assertSame(1, $totals->retireBefore(time() - DetectionTotals::ROLLUP_DAYS * 86400));
		$this->assertSame(0, $totals->retireBefore(time() - DetectionTotals::ROLLUP_DAYS * 86400));
		$this->assertSame(2, $totals->totals()[0]['count']);
		$this->assertSame(1, array_sum(array_column($totals->perDay(time() - 300 * 86400, 0), 'count')), 'the chart has the recent hours only');
	}

	public function testTheBackfillCountsStoredDetectionsOnce(): void {
		$this->insert('trap_url', 'low', false, time() - 7200, count: false);
		$this->insert('trap_url', 'low', false, time() - 7200, count: false);
		$this->insert('admin_change', 'high', true, time(), count: false);
		$totals = Server::get(DetectionTotals::class);
		$totals->backfill();
		$totals->backfill();
		$this->assertSame([
			['check' => 'admin_change', 'severity' => 'high', 'enforced' => true, 'count' => 1],
			['check' => 'trap_url', 'severity' => 'low', 'enforced' => false, 'count' => 2],
		], $totals->totals());
	}

	private function insert(string $check, string $severity, bool $enforced, int $createdAt, bool $count = true): void {
		$detection = new Detection();
		$detection->setCheckId($check);
		$detection->setSeverity($severity);
		$detection->setEnforced($enforced);
		$detection->setExplanationData([]);
		$detection->setActionList([]);
		$detection->setCreatedAt($createdAt);
		$detection->setLastSeenAt($createdAt);
		$detection->setHits(1);
		$detection = Server::get(DetectionMapper::class)->insert($detection);
		if ($count) {
			Server::get(DetectionTotals::class)->created($detection);
		}
	}
}
