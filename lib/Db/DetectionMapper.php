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
 * @template-extends QBMapper<Detection>
 */
class DetectionMapper extends QBMapper {
	public const TABLE = 'ids_detections';

	public function __construct(IDBConnection $db) {
		parent::__construct($db, self::TABLE, Detection::class);
	}

	/**
	 * The most recent detection with this merge key seen since the given time.
	 */
	public function findMergeable(string $mergeKey, int $since): ?Detection {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->eq('merge_key', $qb->createNamedParameter($mergeKey)))
			->andWhere($qb->expr()->gte('last_seen_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->orderBy('last_seen_at', 'DESC')
			->setMaxResults(1);
		$entities = $this->findEntities($qb);
		return $entities[0] ?? null;
	}

	/**
	 * @throws DoesNotExistException
	 */
	public function findById(int $id): Detection {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)));
		return $this->findEntity($qb);
	}

	/**
	 * @return list<Detection> newest first
	 */
	public function findList(DetectionFilter $filter): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')->from(self::TABLE);
		$this->applyFilter($qb, $filter);
		$qb->orderBy('created_at', 'DESC')
			->addOrderBy('id', 'DESC')
			->setMaxResults($filter->limit)
			->setFirstResult($filter->offset);
		return $this->findEntities($qb);
	}

	public function count(DetectionFilter $filter): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*', 'n'))->from(self::TABLE);
		$this->applyFilter($qb, $filter);
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	/**
	 * Detections per check, split by enforced or observed, since a time.
	 *
	 * @return array<string, array{enforced: int, observed: int, hits: int}>
	 */
	public function countByCheck(int $since): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('check_id', 'enforced')
			->selectAlias($qb->func()->count('*'), 'n')
			->selectAlias($qb->func()->sum('hits'), 'h')
			->from(self::TABLE)
			->where($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->groupBy('check_id', 'enforced');
		$result = $qb->executeQuery();
		$counts = [];
		while ($row = $result->fetch()) {
			$check = (string)$row['check_id'];
			$counts[$check] ??= ['enforced' => 0, 'observed' => 0, 'hits' => 0];
			$counts[$check][(bool)$row['enforced'] ? 'enforced' : 'observed'] += (int)$row['n'];
			$counts[$check]['hits'] += (int)$row['h'];
		}
		$result->closeCursor();
		return $counts;
	}

	public function deleteCreatedBefore(int $before): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->lt('created_at', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement();
	}

	private function applyFilter(IQueryBuilder $qb, DetectionFilter $filter): void {
		$expr = $qb->expr();
		if ($filter->checkIds !== []) {
			$qb->andWhere($expr->in('check_id', $qb->createNamedParameter($filter->checkIds, IQueryBuilder::PARAM_STR_ARRAY)));
		}
		if ($filter->severities !== []) {
			$qb->andWhere($expr->in('severity', $qb->createNamedParameter($filter->severities, IQueryBuilder::PARAM_STR_ARRAY)));
		}
		if ($filter->uid !== null) {
			$qb->andWhere($expr->eq('uid', $qb->createNamedParameter($filter->uid)));
		}
		if ($filter->ip !== null) {
			$qb->andWhere($expr->eq('ip', $qb->createNamedParameter($filter->ip)));
		}
		if ($filter->enforced !== null) {
			$qb->andWhere($filter->enforced
				? $expr->eq('enforced', $qb->createNamedParameter(true, IQueryBuilder::PARAM_BOOL))
				: $expr->orX(
					$expr->eq('enforced', $qb->createNamedParameter(false, IQueryBuilder::PARAM_BOOL)),
					$expr->isNull('enforced'),
				));
		}
		if ($filter->since !== null) {
			$qb->andWhere($expr->gte('created_at', $qb->createNamedParameter($filter->since, IQueryBuilder::PARAM_INT)));
		}
		if ($filter->until !== null) {
			$qb->andWhere($expr->lte('created_at', $qb->createNamedParameter($filter->until, IQueryBuilder::PARAM_INT)));
		}
	}
}
