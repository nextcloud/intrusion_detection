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
	 * Delete bans that ended before the given time. They are kept that long for escalation.
	 */
	public function deleteEndedBefore(int $before): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->lt('expires_at', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement();
	}
}
