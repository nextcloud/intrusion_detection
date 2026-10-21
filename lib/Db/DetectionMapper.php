<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCA\IntrusionDetection\Net\SourceKey;
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
	 * Which of the given checks had an enforced detection for the address
	 * that was seen since a time: the address itself for IPv4, its /64 for
	 * IPv6. Detections only observed (learning mode, Observe) do not count.
	 *
	 * @param list<string> $checkIds
	 * @return list<string> check ids
	 */
	public function checksSeenFrom(SourceKey $source, array $checkIds, int $since): array {
		if ($checkIds === []) {
			return [];
		}
		$qb = $this->db->getQueryBuilder();
		$qb->selectDistinct('check_id')
			->from(self::TABLE)
			->where($source->family === 4
				? $qb->expr()->eq('ip', $qb->createNamedParameter($source->ip))
				: $qb->expr()->eq('net_key', $qb->createNamedParameter($source->netKey)))
			->andWhere($qb->expr()->in('check_id', $qb->createNamedParameter($checkIds, IQueryBuilder::PARAM_STR_ARRAY)))
			->andWhere($qb->expr()->gte('last_seen_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('enforced', $qb->createNamedParameter(true, IQueryBuilder::PARAM_BOOL)));
		$result = $qb->executeQuery();
		$ids = [];
		while (($id = $result->fetchOne()) !== false) {
			$ids[] = (string)$id;
		}
		$result->closeCursor();
		sort($ids);
		return $ids;
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
	 * Detections per check, split by enforced or observed, since a time
	 * (and before another, if given).
	 *
	 * @return array<string, array{enforced: int, observed: int, hits: int}>
	 */
	public function countByCheck(int $since, ?int $until = null): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('check_id', 'enforced')
			->selectAlias($qb->func()->count('*'), 'n')
			->selectAlias($qb->func()->sum('hits'), 'h')
			->from(self::TABLE)
			->where($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->groupBy('check_id', 'enforced')
			->orderBy('check_id')
			->addOrderBy('enforced');
		if ($until !== null) {
			$qb->andWhere($qb->expr()->lt('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)));
		}
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

	/**
	 * @param list<int> $ids
	 * @return list<Detection> in id order
	 */
	public function findByIds(array $ids): array {
		if ($ids === []) {
			return [];
		}
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->in('id', $qb->createNamedParameter($ids, IQueryBuilder::PARAM_INT_ARRAY)))
			->orderBy('id', 'ASC');
		return $this->findEntities($qb);
	}

	/**
	 * Record a user's answer to "Was this you?", only if the detection is
	 * theirs and has no answer yet, in one statement.
	 *
	 * @param Detection::VERDICT_* $verdict
	 * @return bool whether this answer was recorded
	 */
	public function setVerdict(int $id, string $uid, string $verdict, int $now): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('user_verdict', $qb->createNamedParameter($verdict))
			->set('verdict_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->isNull('user_verdict'));
		return $qb->executeStatement() === 1;
	}

	/**
	 * Detections of an account, or of an address, that were active in a
	 * period: started before its end and last seen after its start. An
	 * account matches the detections recorded for it
	 * ({@see DetectionAccountMapper}): its own and those that named it, which
	 * callers check in the decoded facts. An address matches by `ip`, an IPv6
	 * network by `net_key`. Oldest first, after a detection for the next page.
	 *
	 * @return list<Detection>
	 */
	public function findForIncident(?string $uid, ?string $ip, ?string $netKey, int $since, int $until, int $limit, ?Detection $after = null): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('d.*')->from(self::TABLE, 'd');
		if ($uid !== null) {
			$qb->innerJoin('d', DetectionAccountMapper::TABLE, 'a', $qb->expr()->eq('a.detection_id', 'd.id'))
				->where($qb->expr()->eq('a.uid', $qb->createNamedParameter($uid)));
		} elseif ($ip !== null) {
			$qb->where($qb->expr()->eq('d.ip', $qb->createNamedParameter($ip)));
		} elseif ($netKey !== null) {
			$qb->where($qb->expr()->eq('d.net_key', $qb->createNamedParameter($netKey)));
		} else {
			return [];
		}
		$qb->andWhere($qb->expr()->lte('d.created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->gte('d.last_seen_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)));
		self::after($qb, $after);
		$qb->orderBy('d.created_at', 'ASC')
			->addOrderBy('d.id', 'ASC')
			->setMaxResults($limit);
		return $this->findEntities($qb);
	}

	/**
	 * Detections of one check created in a period, oldest first, after a
	 * detection for the next page: of an account (recorded for it, e.g. as
	 * the actor of an administration change), or whose explanation contains
	 * a text. Callers check the decoded facts as well, as the account or the
	 * text may also occur elsewhere.
	 *
	 * @return list<Detection>
	 */
	public function findOfCheckFor(string $checkId, ?string $uid, ?string $jsonText, int $since, int $until, int $limit, ?Detection $after = null): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('d.*')
			->from(self::TABLE, 'd')
			->where($qb->expr()->eq('d.check_id', $qb->createNamedParameter($checkId)))
			->andWhere($qb->expr()->gte('d.created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lte('d.created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)));
		if ($uid !== null) {
			$qb->innerJoin('d', DetectionAccountMapper::TABLE, 'a', $qb->expr()->eq('a.detection_id', 'd.id'))
				->andWhere($qb->expr()->eq('a.uid', $qb->createNamedParameter($uid)));
		}
		if ($jsonText !== null) {
			$qb->andWhere($qb->expr()->like('d.explanation', $qb->createNamedParameter('%' . $this->db->escapeLikeParameter($jsonText) . '%')));
		}
		self::after($qb, $after);
		$qb->orderBy('d.created_at', 'ASC')
			->addOrderBy('d.id', 'ASC')
			->setMaxResults($limit);
		return $this->findEntities($qb);
	}

	/**
	 * Only rows after a detection in (created_at, id) order.
	 */
	private static function after(IQueryBuilder $qb, ?Detection $after): void {
		if ($after === null) {
			return;
		}
		$createdAt = $qb->createNamedParameter((int)$after->getCreatedAt(), IQueryBuilder::PARAM_INT);
		$qb->andWhere($qb->expr()->orX(
			$qb->expr()->gt('d.created_at', $createdAt),
			$qb->expr()->andX(
				$qb->expr()->eq('d.created_at', $createdAt),
				$qb->expr()->gt('d.id', $qb->createNamedParameter((int)$after->getId(), IQueryBuilder::PARAM_INT)),
			),
		));
	}

	/**
	 * The key of a check, severity and enforcement in the running totals.
	 */
	public static function labelKey(string $checkId, string $severity, bool $enforced): string {
		return $checkId . '|' . $severity . '|' . ($enforced ? '1' : '0');
	}

	/**
	 * Delete the detections created before a time, in batches, with the
	 * accounts recorded for them.
	 */
	public function deleteCreatedBefore(int $before): int {
		return BatchedDelete::run(
			$this->db,
			self::TABLE,
			'id',
			static fn (IQueryBuilder $qb): IQueryBuilder => $qb->where($qb->expr()->lt('created_at', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT))),
			beforeDelete: function (array $ids): void {
				$qb = $this->db->getQueryBuilder();
				$qb->delete(DetectionAccountMapper::TABLE)
					->where($qb->expr()->in('detection_id', $qb->createNamedParameter($ids, IQueryBuilder::PARAM_INT_ARRAY)))
					->executeStatement();
			},
		);
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
		if ($filter->afterId !== null) {
			$qb->andWhere($expr->gt('id', $qb->createNamedParameter($filter->afterId, IQueryBuilder::PARAM_INT)));
		}
		if ($filter->answered !== null) {
			$qb->andWhere($filter->answered ? $expr->isNotNull('user_verdict') : $expr->isNull('user_verdict'));
		}
	}
}
