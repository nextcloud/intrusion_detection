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
 * @template-extends QBMapper<Approval>
 */
class ApprovalMapper extends QBMapper {
	public const TABLE = 'ids_approvals';

	public function __construct(IDBConnection $db) {
		parent::__construct($db, self::TABLE, Approval::class);
	}

	/**
	 * @throws DoesNotExistException
	 */
	public function findById(int $id): Approval {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)));
		return $this->findEntity($qb);
	}

	/**
	 * The pending request of a kind for one account and group, if there is one.
	 */
	public function findPending(string $kind, string $subjectUid, ?string $groupId): ?Approval {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->eq('subject_uid', $qb->createNamedParameter($subjectUid)))
			->andWhere($qb->expr()->eq('status', $qb->createNamedParameter(Approval::STATUS_PENDING)))
			->andWhere($qb->expr()->eq('kind', $qb->createNamedParameter($kind)))
			->orderBy('id', 'DESC')
			->setMaxResults(1);
		if ($groupId !== null) {
			$qb->andWhere($qb->expr()->eq('group_id', $qb->createNamedParameter($groupId)));
		}
		$entities = $this->findEntities($qb);
		return $entities[0] ?? null;
	}

	/**
	 * @param ?string $kind only requests of this kind
	 * @return list<Approval> newest first; all statuses, or only pending ones
	 */
	public function findList(bool $pendingOnly, int $limit = 200, ?string $kind = null): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->orderBy('created_at', 'DESC')
			->addOrderBy('id', 'DESC')
			->setMaxResults($limit);
		if ($pendingOnly) {
			$qb->andWhere($qb->expr()->eq('status', $qb->createNamedParameter(Approval::STATUS_PENDING)));
		}
		if ($kind !== null) {
			$qb->andWhere($qb->expr()->eq('kind', $qb->createNamedParameter($kind)));
		}
		return $this->findEntities($qb);
	}

	/**
	 * How many requests of a kind about one account are pending and not expired.
	 */
	public function countPendingFor(string $kind, string $subjectUid, int $now): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*'))
			->from(self::TABLE)
			->where($qb->expr()->eq('subject_uid', $qb->createNamedParameter($subjectUid)))
			->andWhere($qb->expr()->eq('status', $qb->createNamedParameter(Approval::STATUS_PENDING)))
			->andWhere($qb->expr()->eq('kind', $qb->createNamedParameter($kind)))
			->andWhere($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	public function countPending(): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*'))
			->from(self::TABLE)
			->where($qb->expr()->eq('status', $qb->createNamedParameter(Approval::STATUS_PENDING)));
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	/**
	 * Pending requests per kind.
	 *
	 * @return array<string, int>
	 */
	public function countPendingByKind(): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('kind')
			->selectAlias($qb->func()->count('*'), 'n')
			->from(self::TABLE)
			->where($qb->expr()->eq('status', $qb->createNamedParameter(Approval::STATUS_PENDING)))
			->groupBy('kind')
			->orderBy('kind');
		$result = $qb->executeQuery();
		$counts = [];
		while ($row = $result->fetch()) {
			$counts[(string)$row['kind']] = (int)$row['n'];
		}
		$result->closeCursor();
		return $counts;
	}

	/**
	 * Requests about, by or decided by an account, or from an address: the
	 * pending ones made in a period, or (with `$decided`) the ones decided in
	 * it, in that order.
	 *
	 * @return list<Approval>
	 */
	public function findForIncident(?string $uid, ?string $ip, bool $decided, int $since, int $until, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$expr = $qb->expr();
		$qb->select('*')->from(self::TABLE);
		if ($uid !== null) {
			$qb->where($expr->orX(
				$expr->eq('subject_uid', $qb->createNamedParameter($uid)),
				$expr->eq('requested_by', $qb->createNamedParameter($uid)),
				$expr->eq('decided_by', $qb->createNamedParameter($uid)),
			));
		} elseif ($ip !== null) {
			$qb->where($expr->eq('ip', $qb->createNamedParameter($ip)));
		} else {
			return [];
		}
		$column = $decided ? 'decided_at' : 'created_at';
		$qb->andWhere($decided
			? $expr->neq('status', $qb->createNamedParameter(Approval::STATUS_PENDING))
			: $expr->eq('status', $qb->createNamedParameter(Approval::STATUS_PENDING)))
			->andWhere($expr->gte($column, $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($expr->lte($column, $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->orderBy($column, 'ASC')
			->addOrderBy('id', 'ASC')
			->setMaxResults($limit);
		return $this->findEntities($qb);
	}

	/**
	 * @return list<Approval> pending requests whose time ran out
	 */
	public function findExpired(int $now, int $limit = 500): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->eq('status', $qb->createNamedParameter(Approval::STATUS_PENDING)))
			->andWhere($qb->expr()->lte('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)))
			->setMaxResults($limit);
		return $this->findEntities($qb);
	}

	/**
	 * End a pending request. Only one caller can win: the update only applies
	 * while the request is still pending, so two administrators deciding at
	 * the same moment cannot both succeed.
	 *
	 * @return bool whether this call decided it
	 */
	public function decide(int $id, string $status, ?string $decidedBy, int $now): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('status', $qb->createNamedParameter($status))
			->set('decided_by', $qb->createNamedParameter($decidedBy))
			->set('decided_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('status', $qb->createNamedParameter(Approval::STATUS_PENDING)));
		return $qb->executeStatement() === 1;
	}

	/**
	 * Remove decided requests older than a time. Pending ones are kept until
	 * they expire.
	 */
	public function deleteDecidedBefore(int $before): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->neq('status', $qb->createNamedParameter(Approval::STATUS_PENDING)))
			->andWhere($qb->expr()->lt('created_at', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement();
	}
}
