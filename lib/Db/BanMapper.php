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
 * @template-extends QBMapper<Ban>
 */
class BanMapper extends QBMapper {
	public const TABLE = 'ids_bans';

	public function __construct(IDBConnection $db) {
		parent::__construct($db, self::TABLE, Ban::class);
	}

	/**
	 * Bans of one key created since the given time, lifted or not, for escalation.
	 */
	public function countSince(string $banKey, int $since): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*', 'n'))
			->from(self::TABLE)
			->where($qb->expr()->eq('ban_key', $qb->createNamedParameter($banKey)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	/**
	 * Active single-address bans inside one IPv4 /24, created since the given time.
	 *
	 * @return list<Ban>
	 */
	public function findActiveInNet(string $netPrefix, int $since, int $now): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->like('ban_key', $qb->createNamedParameter($this->db->escapeLikeParameter($netPrefix) . '%')))
			->andWhere($qb->expr()->eq('scope', $qb->createNamedParameter(Ban::SCOPE_IP)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->isNull('lifted_at'));
		return $this->findEntities($qb);
	}

	/**
	 * @throws DoesNotExistException
	 */
	public function findByReference(string $reference): Ban {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->eq('reference', $qb->createNamedParameter(Ban::normaliseReference($reference))));
		return $this->findEntity($qb);
	}

	/**
	 * @throws DoesNotExistException
	 */
	public function findById(int $id): Ban {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)));
		return $this->findEntity($qb);
	}

	public function referenceExists(string $reference): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id')
			->from(self::TABLE)
			->where($qb->expr()->eq('reference', $qb->createNamedParameter($reference)))
			->setMaxResults(1);
		$result = $qb->executeQuery();
		$exists = $result->fetchOne() !== false;
		$result->closeCursor();
		return $exists;
	}

	/**
	 * @return list<Ban> active bans first by expiry, or every ban when $includeInactive
	 */
	public function findList(int $now, bool $includeInactive = false, int $limit = 200, int $offset = 0): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')->from(self::TABLE);
		if (!$includeInactive) {
			$qb->where($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)))
				->andWhere($qb->expr()->isNull('lifted_at'))
				->orderBy('expires_at', 'ASC');
		} else {
			$qb->orderBy('created_at', 'DESC');
		}
		$qb->setMaxResults($limit)->setFirstResult($offset);
		return $this->findEntities($qb);
	}

	/**
	 * Active bans for a list of ban keys: what blocks an address right now.
	 *
	 * @param list<string> $banKeys
	 * @return list<Ban>
	 */
	public function findActiveForKeys(array $banKeys, int $now): array {
		if ($banKeys === []) {
			return [];
		}
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->in('ban_key', $qb->createNamedParameter($banKeys, IQueryBuilder::PARAM_STR_ARRAY)))
			->andWhere($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->isNull('lifted_at'));
		return $this->findEntities($qb);
	}

	public function countActive(int $now): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*', 'n'))
			->from(self::TABLE)
			->where($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->isNull('lifted_at'));
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	/**
	 * Bans of these keys, or caused by detections of an account, that were
	 * created (or, with `$lifted`, lifted) in a period, in that order.
	 *
	 * @param list<string> $banKeys
	 * @return list<Ban>
	 */
	public function findForIncident(array $banKeys, ?string $uid, bool $lifted, int $since, int $until, int $limit): array {
		$column = $lifted ? 'b.lifted_at' : 'b.created_at';
		$qb = $this->db->getQueryBuilder();
		$qb->select('b.*')->from(self::TABLE, 'b');
		if ($uid !== null) {
			$qb->innerJoin('b', DetectionMapper::TABLE, 'd', $qb->expr()->eq('b.detection_id', 'd.id'))
				->where($qb->expr()->eq('d.uid', $qb->createNamedParameter($uid)));
		} elseif ($banKeys !== []) {
			$qb->where($qb->expr()->in('b.ban_key', $qb->createNamedParameter($banKeys, IQueryBuilder::PARAM_STR_ARRAY)));
		} else {
			return [];
		}
		$qb->andWhere($qb->expr()->gte($column, $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lte($column, $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->orderBy($column, 'ASC')
			->addOrderBy('b.id', 'ASC')
			->setMaxResults($limit);
		return $this->findEntities($qb);
	}

	/**
	 * Active bans per scope and level.
	 *
	 * @return list<array{scope: string, level: int, count: int}>
	 */
	public function countActiveByScopeAndLevel(int $now): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('scope', 'level')
			->selectAlias($qb->func()->count('*'), 'n')
			->from(self::TABLE)
			->where($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->isNull('lifted_at'))
			->groupBy('scope', 'level')
			->orderBy('scope')
			->addOrderBy('level');
		$result = $qb->executeQuery();
		$rows = [];
		while ($row = $result->fetch()) {
			$rows[] = ['scope' => (string)$row['scope'], 'level' => (int)$row['level'], 'count' => (int)$row['n']];
		}
		$result->closeCursor();
		return $rows;
	}

	/**
	 * Delete bans that ended before the given time. They are kept that long for escalation.
	 */
	public function deleteEndedBefore(int $before): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->lt('expires_at', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement();
	}
}
