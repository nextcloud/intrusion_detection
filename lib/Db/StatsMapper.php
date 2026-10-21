<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

/**
 * Read-only aggregates for the admin page and the dashboard widget. Every
 * query is bounded by a time window on an indexed column.
 */
class StatsMapper {
	public const DAY = 86400;

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * Bans created since a time, lifted or not.
	 *
	 * A ban created since then also ends at or after that time, so the
	 * condition on `expires_at` lets the expiry index narrow the scan.
	 */
	public function bansCreatedSince(int $since): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*', 'n'))
			->from(BanMapper::TABLE)
			->where($qb->expr()->gte('expires_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	/**
	 * Bans created since a time, per check.
	 *
	 * @return array<string, int>
	 */
	public function bansCreatedByCheck(int $since): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('check_id')
			->selectAlias($qb->func()->count('*'), 'n')
			->from(BanMapper::TABLE)
			->where($qb->expr()->gte('expires_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->groupBy('check_id');
		$result = $qb->executeQuery();
		$counts = [];
		while ($row = $result->fetch()) {
			$counts[(string)$row['check_id']] = (int)$row['n'];
		}
		$result->closeCursor();
		return $counts;
	}

	/**
	 * Distinct accounts that detections since a time were about.
	 */
	public function accountsSince(int $since): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->createFunction('COUNT(DISTINCT ' . $qb->getColumnName('uid') . ')'))
			->from(DetectionMapper::TABLE)
			->where($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->isNotNull('uid'));
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	/**
	 * Distinct addresses that observed detections since a time would have
	 * blocked: those whose recorded actions include a ban that was not carried out.
	 *
	 * At most `$limit` detections are read; detections of one source are
	 * merged per hour, so that covers even a busy day.
	 */
	public function wouldHaveBlockedSince(int $since, int $limit = 5000): int {
		$qb = $this->db->getQueryBuilder();
		$expr = $qb->expr();
		$qb->select('ip', 'actions')
			->from(DetectionMapper::TABLE)
			->where($expr->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($expr->isNotNull('ip'))
			->andWhere($expr->orX(
				$expr->eq('enforced', $qb->createNamedParameter(false, IQueryBuilder::PARAM_BOOL)),
				$expr->isNull('enforced'),
			))
			->setMaxResults($limit);
		$result = $qb->executeQuery();
		$addresses = [];
		while ($row = $result->fetch()) {
			$detection = new Detection();
			$detection->setActions(is_string($row['actions']) ? $row['actions'] : null);
			foreach ($detection->getActionList() as $action) {
				if ($action['type'] === 'ban' && !$action['enforced']) {
					$addresses[(string)$row['ip']] = true;
					break;
				}
			}
		}
		$result->closeCursor();
		return count($addresses);
	}

	/**
	 * Detections per local day, check and enforcement, since a time.
	 *
	 * @param int $offset seconds to add to UTC to get local time; days start at local midnight
	 * @return list<array{bucket: int, checkId: string, enforced: bool, count: int}> `bucket` is the local day number since the epoch
	 */
	public function detectionsPerDay(int $since, int $offset): array {
		$qb = $this->db->getQueryBuilder();
		$shifted = '(' . $qb->getColumnName('created_at') . ($offset >= 0 ? ' + ' : ' - ') . abs($offset) . ')';
		$bucket = match ($this->db->getDatabaseProvider()) {
			IDBConnection::PLATFORM_MYSQL, IDBConnection::PLATFORM_MARIADB => $shifted . ' DIV ' . self::DAY,
			IDBConnection::PLATFORM_ORACLE => 'FLOOR(' . $shifted . ' / ' . self::DAY . ')',
			// Integer division: created_at is an integer column.
			default => $shifted . ' / ' . self::DAY,
		};
		$qb->selectAlias($qb->createFunction($bucket), 'bucket')
			->addSelect('check_id', 'enforced')
			->selectAlias($qb->func()->count('*'), 'n')
			->from(DetectionMapper::TABLE)
			->where($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->groupBy($qb->createFunction($bucket))
			->addGroupBy('check_id', 'enforced');
		$result = $qb->executeQuery();
		$rows = [];
		while ($row = $result->fetch()) {
			$rows[] = [
				'bucket' => (int)$row['bucket'],
				'checkId' => (string)$row['check_id'],
				'enforced' => (bool)$row['enforced'],
				'count' => (int)$row['n'],
			];
		}
		$result->closeCursor();
		return $rows;
	}
}
