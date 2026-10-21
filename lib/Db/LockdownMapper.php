<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Db\QBMapper;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

/**
 * @template-extends QBMapper<Lockdown>
 */
class LockdownMapper extends QBMapper {
	public const TABLE = 'ids_lockdowns';

	public function __construct(IDBConnection $db) {
		parent::__construct($db, self::TABLE, Lockdown::class);
	}

	public function findById(int $id): ?Lockdown {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)));
		try {
			return $this->findEntity($qb);
		} catch (DoesNotExistException) {
			return null;
		}
	}

	/**
	 * @return list<Lockdown> the latest lockdowns, newest first
	 */
	public function latest(int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->orderBy('started_at', 'DESC')
			->addOrderBy('id', 'DESC')
			->setMaxResults($limit);
		return $this->findEntities($qb);
	}

	/**
	 * The lockdowns that were on at some point of a period, oldest first.
	 *
	 * @return list<Lockdown>
	 */
	public function overlapping(int $since, int $until, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->lte('started_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->orX(
				$qb->expr()->gte('ended_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)),
				$qb->expr()->andX(
					$qb->expr()->isNull('ended_at'),
					$qb->expr()->gte('planned_end', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)),
				),
			))
			->orderBy('started_at', 'ASC')
			->setMaxResults($limit);
		return $this->findEntities($qb);
	}

	/**
	 * Delete lockdowns that ended before a time.
	 */
	public function deleteEndedBefore(int $before): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->lt('planned_end', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->orX(
				$qb->expr()->isNull('ended_at'),
				$qb->expr()->lt('ended_at', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT)),
			));
		return $qb->executeStatement();
	}
}
