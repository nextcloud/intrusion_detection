<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Admin\CheckList;
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
use OCP\L10N\IFactory;
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

	public function testTheLastSevenDaysPerCheckComeFromTheHourlyTable(): void {
		$now = time();
		for ($i = 0; $i < 30; $i++) {
			$this->insert('trap_url', $i % 3 === 0 ? 'medium' : 'low', $i % 2 === 0, $now - $i * 3600);
		}
		$this->insert('admin_change', 'high', true, $now - 86400);
		$this->insert('admin_change', 'high', true, $now - 8 * 86400);

		$queries = $this->db->getInner()->getStats()['executed'];
		$counts = Server::get(DetectionTotals::class)->perCheck($now - 7 * 86400);
		$this->assertSame(1, $this->db->getInner()->getStats()['executed'] - $queries, 'one grouped query');
		$this->assertSame(['enforced' => 15, 'observed' => 15], $counts['trap_url']);
		$this->assertSame(['enforced' => 1, 'observed' => 0], $counts['admin_change'], 'the older one is not counted');
	}

	public function testPeriodsThatFollowEachOtherCountEveryHourOnce(): void {
		$hour = intdiv(time(), 3600) * 3600 - 10 * 3600;
		$this->insert('trap_url', 'low', true, $hour);
		$this->insert('trap_url', 'low', true, $hour + 1800);
		$this->insert('trap_url', 'low', false, $hour + 3600);
		$this->insert('trap_url', 'low', true, $hour + 7200);
		$totals = Server::get(DetectionTotals::class);

		$this->assertSame(['trap_url' => ['enforced' => 2, 'observed' => 0]], $totals->perCheckBetween($hour, $hour + 3600));
		$this->assertSame(['trap_url' => ['enforced' => 0, 'observed' => 1]], $totals->perCheckBetween($hour + 3600, $hour + 7200));
		$this->assertSame([], $totals->perCheckBetween($hour - 3600, $hour), 'the end is not part of a period');
		// Half-hour boundaries: the hour that starts within a period belongs to it.
		$this->assertSame(['trap_url' => ['enforced' => 0, 'observed' => 1]], $totals->perCheckBetween($hour + 1800, $hour + 5400));
		$this->assertSame(['trap_url' => ['enforced' => 1, 'observed' => 0]], $totals->perCheckBetween($hour + 5400, $hour + 9000));
		$this->assertSame(['trap_url' => ['enforced' => 2, 'observed' => 0]], $totals->perCheckBetween($hour - 1800, $hour + 1800));
	}

	public function testTheCheckListCostsTheSameForManyDetections(): void {
		$list = Server::get(CheckList::class);
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$this->insert('trap_url', 'low', false, time());
		$queries = $this->db->getInner()->getStats()['executed'];
		$list->all($l);
		$few = $this->db->getInner()->getStats()['executed'] - $queries;

		for ($i = 0; $i < 200; $i++) {
			$this->insert('trap_url', 'low', $i % 2 === 0, time() - $i * 600);
		}
		$queries = $this->db->getInner()->getStats()['executed'];
		$result = $list->all($l);
		$this->assertSame($few, $this->db->getInner()->getStats()['executed'] - $queries, 'the counts do not read the detections');
		$trap = array_values(array_filter($result['checks'], static fn (array $check): bool => $check['id'] === 'trap_url'))[0];
		$this->assertSame(201, $trap['stats']['detections']);
		$this->assertSame(100, $trap['stats']['enforced']);
		$this->assertSame(7, $trap['stats']['days']);
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
