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
 * Failed logins per account and UTC day (ids_user_daily), one row per
 * account and day. Every query uses the unique index (uid, day), except the
 * cleanup, which uses the index on day.
 */
class UserDailyMapper {
	public const TABLE = 'ids_user_daily';

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * @return ?array{failed_logins: int, hours: ?string, sources: ?string}
	 */
	public function find(string $uid, int $day): ?array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('failed_logins', 'hours', 'sources')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->eq('day', $qb->createNamedParameter($day, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		if ($row === false) {
			return null;
		}
		return [
			'failed_logins' => (int)$row['failed_logins'],
			'hours' => $row['hours'] === null ? null : (string)$row['hours'],
			'sources' => $row['sources'] === null ? null : (string)$row['sources'],
		];
	}

	/**
	 * The first failure of the day.
	 *
	 * @return bool false when another request created the day's row first
	 */
	public function insert(string $uid, int $day, string $hours, string $sources, int $now): bool {
		return $this->db->insertIgnoreConflict(self::TABLE, [
			'uid' => $uid,
			'day' => $day,
			'failed_logins' => 1,
			'hours' => $hours,
			'sources' => $sources,
			'updated_at' => $now,
		]) > 0;
	}

	/**
	 * Count one more failure with the new hours and sources, unless another
	 * request counted one since the row was read.
	 *
	 * @param int $seen the count that was read
	 * @return bool whether the row still had that count and was updated
	 */
	public function replace(string $uid, int $day, int $seen, string $hours, string $sources, int $now): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('failed_logins', $qb->createNamedParameter($seen + 1, IQueryBuilder::PARAM_INT))
			->set('hours', $qb->createNamedParameter($hours))
			->set('sources', $qb->createNamedParameter($sources))
			->set('updated_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->eq('day', $qb->createNamedParameter($day, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('failed_logins', $qb->createNamedParameter($seen, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement() > 0;
	}

	/**
	 * Count one more failure without touching the hours and sources.
	 */
	public function increment(string $uid, int $day, int $now): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('failed_logins', $qb->func()->add('failed_logins', $qb->createNamedParameter(1, IQueryBuilder::PARAM_INT)))
			->set('updated_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->eq('day', $qb->createNamedParameter($day, IQueryBuilder::PARAM_INT)))
			->executeStatement();
	}

	/**
	 * @return list<array{day: int, failed_logins: int, hours: ?string, sources: ?string, updated_at: int}> oldest first
	 */
	public function forUser(string $uid, int $sinceDay, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('day', 'failed_logins', 'hours', 'sources', 'updated_at')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->gte('day', $qb->createNamedParameter($sinceDay, IQueryBuilder::PARAM_INT)))
			->orderBy('day', 'ASC')
			->setMaxResults($limit);
		$result = $qb->executeQuery();
		$rows = [];
		while ($row = $result->fetch()) {
			$rows[] = [
				'day' => (int)$row['day'],
				'failed_logins' => (int)$row['failed_logins'],
				'hours' => $row['hours'] === null ? null : (string)$row['hours'],
				'sources' => $row['sources'] === null ? null : (string)$row['sources'],
				'updated_at' => (int)$row['updated_at'],
			];
		}
		$result->closeCursor();
		return $rows;
	}

	public function deleteBefore(int $day): int {
		return BatchedDelete::run($this->db, self::TABLE, 'id', 'day', static fn (IQueryBuilder $qb): IQueryBuilder => $qb->where($qb->expr()->lt('day', $qb->createNamedParameter($day, IQueryBuilder::PARAM_INT))));
	}
}
