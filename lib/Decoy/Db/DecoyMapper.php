<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Decoy\Db;

use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Db\QBMapper;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;
use OCP\Snowflake\ISnowflakeGenerator;

/**
 * @template-extends QBMapper<Decoy>
 */
class DecoyMapper extends QBMapper {
	public const TABLE = 'ids_decoys';

	public function __construct(
		IDBConnection $db,
		private readonly ISnowflakeGenerator $snowflakes,
	) {
		parent::__construct($db, self::TABLE, Decoy::class);
	}

	/**
	 * Decoys whose secret fingerprint or login name equals the given ones:
	 * two indexed equality lookups, never a loop of comparisons.
	 *
	 * @return list<Decoy>
	 */
	public function findMatching(?string $secretHmac, #[\SensitiveParameter] ?string $loginName): array {
		if ($secretHmac === null && $loginName === null) {
			return [];
		}
		$qb = $this->db->getQueryBuilder();
		$expr = $qb->expr();
		$conditions = [];
		if ($secretHmac !== null) {
			$conditions[] = $expr->eq('secret_hmac', $qb->createNamedParameter($secretHmac));
		}
		if ($loginName !== null) {
			$conditions[] = $expr->eq('login_name', $qb->createNamedParameter($loginName));
		}
		$qb->select('*')
			->from(self::TABLE)
			->where($expr->orX(...$conditions))
			->setMaxResults(5);
		return $this->findEntities($qb);
	}

	public function secretExists(string $secretHmac): bool {
		return $this->findMatching($secretHmac, null) !== [];
	}

	/**
	 * @throws DoesNotExistException
	 */
	public function findById(string $id): Decoy {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id)));
		return $this->findEntity($qb);
	}

	/**
	 * @return list<Decoy> newest first
	 */
	public function findAll(int $limit = 500): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->orderBy('id', 'DESC')
			->setMaxResults($limit);
		return $this->findEntities($qb);
	}

	/**
	 * How many decoys were created before a time, which their ids tell.
	 */
	public function countCreatedBefore(int $before): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*'))
			->from(self::TABLE)
			->where($qb->expr()->lt('id', $qb->createNamedParameter($this->snowflakes->minForTimeId($before))));
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	public function countAll(): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*'))->from(self::TABLE);
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	/**
	 * @return list<string> every login name a decoy uses
	 */
	public function loginNames(): array {
		$qb = $this->db->getQueryBuilder();
		$qb->selectDistinct('login_name')
			->from(self::TABLE)
			->where($qb->expr()->isNotNull('login_name'));
		$result = $qb->executeQuery();
		$names = array_map('strval', $result->fetchFirstColumn());
		$result->closeCursor();
		return $names;
	}

	/**
	 * Count one use, in a single statement so concurrent uses all count.
	 */
	public function markTriggered(string $id, int $now): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('trigger_count', $qb->func()->add('trigger_count', $qb->createNamedParameter(1, IQueryBuilder::PARAM_INT)))
			->set('last_triggered_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id)))
			->executeStatement();
	}
}
