<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\StatsMapper;
use OCA\IntrusionDetection\State\AppState;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

/**
 * Running totals of the detections, per hour, check, severity and
 * enforcement (ids_detection_hourly), for the statistics and the metrics:
 * nothing that counts reads the detections table.
 *
 * - A new detection adds one to `created` of its hour and labels.
 * - A merged hit that raises a detection's severity adds one to `raised`
 *   of the new severity: the detection then counts under both severities,
 *   so every series of the metric only ever grows.
 * - Hours older than ROLLUP_DAYS are folded into one running total per
 *   labels in the app config (`detections_retired`) by the cleanup job.
 *   Detections themselves are deleted after their own retention, which
 *   changes no total.
 */
class DetectionTotals {
	/** Detections deleted after their retention, counted per check, severity and enforcement, for the running total */
	public const RETIRED_STATE = 'detections_retired';
	public const TABLE = 'ids_detection_hourly';
	/** Hours kept for the per-day chart, which shows up to 90 local days */
	public const ROLLUP_DAYS = 100;

	public function __construct(
		private readonly IDBConnection $db,
		private readonly DetectionMapper $mapper,
		private readonly AppState $state,
	) {
	}

	/**
	 * Count a new detection.
	 */
	public function created(Detection $detection): void {
		$this->add('created', intdiv((int)$detection->getCreatedAt(), 3600), (string)$detection->getCheckId(), (string)$detection->getSeverity(), $detection->isEnforced());
	}

	/**
	 * Count a detection whose severity a merged hit raised, under its new severity.
	 */
	public function raised(Detection $detection, int $now): void {
		$this->add('raised', intdiv($now, 3600), (string)$detection->getCheckId(), (string)$detection->getSeverity(), $detection->isEnforced());
	}

	/**
	 * Delete the detections created before a time. The totals keep them.
	 *
	 * @return int how many were deleted
	 */
	public function deleteCreatedBefore(int $before): int {
		return $this->mapper->deleteCreatedBefore($before);
	}

	/**
	 * Fold the hours before a time into the running totals in the app config.
	 *
	 * @return int how many hourly rows were folded
	 */
	public function retireBefore(int $before): int {
		$beforeHour = intdiv($before, 3600);
		$qb = $this->db->getQueryBuilder();
		$qb->select('check_id', 'severity', 'enforced')
			->selectAlias($qb->func()->sum('created'), 'c')
			->selectAlias($qb->func()->sum('raised'), 'r')
			->selectAlias($qb->func()->count('*'), 'n')
			->from(self::TABLE)
			->where($qb->expr()->lt('hour', $qb->createNamedParameter($beforeHour, IQueryBuilder::PARAM_INT)))
			->groupBy('check_id', 'severity', 'enforced');
		$result = $qb->executeQuery();
		$rows = $result->fetchAll();
		$result->closeCursor();
		if ($rows === []) {
			return 0;
		}
		$retired = $this->retired();
		$folded = 0;
		foreach ($rows as $row) {
			$key = DetectionMapper::labelKey((string)$row['check_id'], (string)$row['severity'], (int)$row['enforced'] === 1);
			$retired[$key] = ($retired[$key] ?? 0) + (int)$row['c'] + (int)$row['r'];
			$folded += (int)$row['n'];
		}
		ksort($retired);
		// Written before the rows go: an interruption may count them twice, never lose them.
		$this->state->setJson(self::RETIRED_STATE, $retired);
		$delete = $this->db->getQueryBuilder();
		$delete->delete(self::TABLE)
			->where($delete->expr()->lt('hour', $delete->createNamedParameter($beforeHour, IQueryBuilder::PARAM_INT)))
			->executeStatement();
		return $folded;
	}

	/**
	 * Every detection since installation, by check, severity and enforcement.
	 *
	 * @return list<array{check: string, severity: string, enforced: bool, count: int}>
	 */
	public function totals(): array {
		$totals = $this->retired();
		$qb = $this->db->getQueryBuilder();
		$qb->select('check_id', 'severity', 'enforced')
			->selectAlias($qb->func()->sum('created'), 'c')
			->selectAlias($qb->func()->sum('raised'), 'r')
			->from(self::TABLE)
			->groupBy('check_id', 'severity', 'enforced');
		$result = $qb->executeQuery();
		while ($row = $result->fetch()) {
			$key = DetectionMapper::labelKey((string)$row['check_id'], (string)$row['severity'], (int)$row['enforced'] === 1);
			$totals[$key] = ($totals[$key] ?? 0) + (int)$row['c'] + (int)$row['r'];
		}
		$result->closeCursor();
		ksort($totals);
		$rows = [];
		foreach ($totals as $key => $count) {
			$parts = explode('|', $key);
			if (count($parts) === 3 && $count > 0) {
				$rows[] = ['check' => $parts[0], 'severity' => $parts[1], 'enforced' => $parts[2] === '1', 'count' => $count];
			}
		}
		return $rows;
	}

	/**
	 * New detections per check and enforcement since a time, counted from the
	 * whole hour that contains it. One grouped read of the hourly rows, so
	 * the cost does not grow with the number of detections or checks.
	 *
	 * @return array<string, array{enforced: int, observed: int}> by check id
	 */
	public function perCheck(int $since): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('check_id', 'enforced')
			->selectAlias($qb->func()->sum('created'), 'c')
			->from(self::TABLE)
			->where($qb->expr()->gte('hour', $qb->createNamedParameter(intdiv($since, 3600), IQueryBuilder::PARAM_INT)))
			->groupBy('check_id', 'enforced');
		$result = $qb->executeQuery();
		$counts = [];
		while ($row = $result->fetch()) {
			$check = (string)$row['check_id'];
			$counts[$check] ??= ['enforced' => 0, 'observed' => 0];
			$counts[$check][(int)$row['enforced'] === 1 ? 'enforced' : 'observed'] += (int)$row['c'];
		}
		$result->closeCursor();
		return $counts;
	}

	/**
	 * New detections per check and enforcement in a period, by the hours
	 * that start in it. Periods that follow each other count every hour
	 * once; a period that does not start and end on a whole hour moves by
	 * less than an hour.
	 *
	 * @return array<string, array{enforced: int, observed: int}> by check id
	 */
	public function perCheckBetween(int $since, int $until): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('check_id', 'enforced')
			->selectAlias($qb->func()->sum('created'), 'c')
			->from(self::TABLE)
			->where($qb->expr()->gte('hour', $qb->createNamedParameter(intdiv($since + 3599, 3600), IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lt('hour', $qb->createNamedParameter(intdiv($until + 3599, 3600), IQueryBuilder::PARAM_INT)))
			->groupBy('check_id', 'enforced');
		$result = $qb->executeQuery();
		$counts = [];
		while ($row = $result->fetch()) {
			$check = (string)$row['check_id'];
			$counts[$check] ??= ['enforced' => 0, 'observed' => 0];
			$counts[$check][(int)$row['enforced'] === 1 ? 'enforced' : 'observed'] += (int)$row['c'];
		}
		$result->closeCursor();
		return $counts;
	}

	/**
	 * New detections per local day, check and enforcement, since a time.
	 * Days are made of whole hours, so with a time zone offset that is not a
	 * whole number of hours a day starts up to half an hour early.
	 *
	 * @param int $offset seconds to add to UTC to get local time
	 * @return list<array{bucket: int, checkId: string, enforced: bool, count: int}> `bucket` is the local day number since the epoch
	 */
	public function perDay(int $since, int $offset): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('hour', 'check_id', 'enforced')
			->selectAlias($qb->func()->sum('created'), 'c')
			->from(self::TABLE)
			->where($qb->expr()->gte('hour', $qb->createNamedParameter(intdiv($since, 3600), IQueryBuilder::PARAM_INT)))
			->groupBy('hour', 'check_id', 'enforced');
		$result = $qb->executeQuery();
		$days = [];
		while ($row = $result->fetch()) {
			$count = (int)$row['c'];
			if ($count === 0) {
				continue;
			}
			$bucket = intdiv((int)$row['hour'] * 3600 + $offset, StatsMapper::DAY);
			$key = $bucket . '|' . $row['check_id'] . '|' . (int)$row['enforced'];
			$days[$key] ??= ['bucket' => $bucket, 'checkId' => (string)$row['check_id'], 'enforced' => (int)$row['enforced'] === 1, 'count' => 0];
			$days[$key]['count'] += $count;
		}
		$result->closeCursor();
		return array_values($days);
	}

	/**
	 * Count the detections stored so far, for the time before the totals
	 * existed. Does nothing once any hour is counted.
	 */
	public function backfill(): void {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id')->from(self::TABLE)->setMaxResults(1);
		$result = $qb->executeQuery();
		$counted = $result->fetchOne() !== false;
		$result->closeCursor();
		if ($counted) {
			return;
		}
		$qb = $this->db->getQueryBuilder();
		$hour = match ($this->db->getDatabaseProvider()) {
			IDBConnection::PLATFORM_MYSQL, IDBConnection::PLATFORM_MARIADB => $qb->getColumnName('created_at') . ' DIV 3600',
			IDBConnection::PLATFORM_ORACLE => 'FLOOR(' . $qb->getColumnName('created_at') . ' / 3600)',
			// Integer division: created_at is an integer column.
			default => $qb->getColumnName('created_at') . ' / 3600',
		};
		$qb->selectAlias($qb->createFunction($hour), 'h')
			->addSelect('check_id', 'severity', 'enforced')
			->selectAlias($qb->func()->count('*'), 'n')
			->from(DetectionMapper::TABLE)
			->groupBy($qb->createFunction($hour))
			->addGroupBy('check_id', 'severity', 'enforced');
		$result = $qb->executeQuery();
		while ($row = $result->fetch()) {
			$this->add('created', (int)$row['h'], (string)$row['check_id'], (string)$row['severity'], (bool)$row['enforced'], (int)$row['n']);
		}
		$result->closeCursor();
	}

	/**
	 * Add to a counter of an hour and labels: an update, and an insert the
	 * first time; a concurrent first insert makes the update run again.
	 *
	 * @param 'created'|'raised' $column
	 */
	private function add(string $column, int $hour, string $checkId, string $severity, bool $enforced, int $by = 1): void {
		$update = function () use ($column, $hour, $checkId, $severity, $enforced, $by): int {
			$qb = $this->db->getQueryBuilder();
			return $qb->update(self::TABLE)
				->set($column, $qb->createFunction($qb->getColumnName($column) . ' + ' . $by))
				->where($qb->expr()->eq('hour', $qb->createNamedParameter($hour, IQueryBuilder::PARAM_INT)))
				->andWhere($qb->expr()->eq('check_id', $qb->createNamedParameter($checkId)))
				->andWhere($qb->expr()->eq('severity', $qb->createNamedParameter($severity)))
				->andWhere($qb->expr()->eq('enforced', $qb->createNamedParameter($enforced ? 1 : 0, IQueryBuilder::PARAM_INT)))
				->executeStatement();
		};
		if ($update() > 0) {
			return;
		}
		$inserted = $this->db->insertIgnoreConflict(self::TABLE, [
			'hour' => $hour,
			'check_id' => $checkId,
			'severity' => $severity,
			'enforced' => $enforced ? 1 : 0,
			'created' => $column === 'created' ? $by : 0,
			'raised' => $column === 'raised' ? $by : 0,
		]);
		if ($inserted === 0) {
			$update();
		}
	}

	/**
	 * @return array<string, int>
	 */
	private function retired(): array {
		$retired = [];
		foreach ($this->state->getJson(self::RETIRED_STATE) as $key => $count) {
			if (is_string($key) && is_int($count) && $count > 0) {
				$retired[$key] = $count;
			}
		}
		return $retired;
	}
}
