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
	 * Which of the given checks had a detection for the address that was
	 * seen since a time: the address itself for IPv4, its /64 for IPv6.
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
			->andWhere($qb->expr()->gte('last_seen_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)));
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
	 * Detections of an account, or whose explanation or actions contain a
	 * text (the account's uid as JSON), after an id, oldest first.
	 *
	 * @return list<Detection>
	 */
	public function findMentioning(string $uid, string $jsonText, int $afterId, int $limit): array {
		$needle = '%' . $this->db->escapeLikeParameter($jsonText) . '%';
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->gt('id', $qb->createNamedParameter($afterId, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->orX(
				$qb->expr()->eq('uid', $qb->createNamedParameter($uid)),
				$qb->expr()->like('explanation', $qb->createNamedParameter($needle)),
				$qb->expr()->like('actions', $qb->createNamedParameter($needle)),
			))
			->orderBy('id', 'ASC')
			->setMaxResults($limit);
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
	 * account also matches detections whose explanation contains
	 * `$jsonText` (its uid as JSON, for detections that targeted it), which
	 * callers check in the decoded facts. An address matches by `ip`, an
	 * IPv6 network by `net_key`. Oldest first.
	 *
	 * @return list<Detection>
	 */
	public function findForIncident(?string $uid, ?string $jsonText, ?string $ip, ?string $netKey, int $since, int $until, int $limit, int $offset = 0): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')->from(self::TABLE);
		if ($uid !== null) {
			$qb->where($jsonText === null
				? $qb->expr()->eq('uid', $qb->createNamedParameter($uid))
				: $qb->expr()->orX(
					$qb->expr()->eq('uid', $qb->createNamedParameter($uid)),
					$qb->expr()->like('explanation', $qb->createNamedParameter('%' . $this->db->escapeLikeParameter($jsonText) . '%')),
				));
		} elseif ($ip !== null) {
			$qb->where($qb->expr()->eq('ip', $qb->createNamedParameter($ip)));
		} elseif ($netKey !== null) {
			$qb->where($qb->expr()->eq('net_key', $qb->createNamedParameter($netKey)));
		} else {
			return [];
		}
		$qb->andWhere($qb->expr()->lte('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->gte('last_seen_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->orderBy('created_at', 'ASC')
			->addOrderBy('id', 'ASC')
			->setMaxResults($limit)
			->setFirstResult($offset);
		return $this->findEntities($qb);
	}

	/**
	 * Detections of one check created in a period whose explanation contains
	 * a text, oldest first. Callers check the decoded facts as well, as the
	 * text may also occur elsewhere in the explanation.
	 *
	 * @return list<Detection>
	 */
	public function findOfCheckContaining(string $checkId, string $jsonText, int $since, int $until, int $limit, int $offset = 0): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->eq('check_id', $qb->createNamedParameter($checkId)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lte('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->like('explanation', $qb->createNamedParameter('%' . $this->db->escapeLikeParameter($jsonText) . '%')))
			->orderBy('created_at', 'ASC')
			->addOrderBy('id', 'ASC')
			->setMaxResults($limit)
			->setFirstResult($offset);
		return $this->findEntities($qb);
	}

	/**
	 * How many detections exist per check, severity and enforcement, all of
	 * them or those created before a time.
	 *
	 * @return array<string, int> keyed by {@see self::labelKey()}
	 */
	public function countByLabels(?int $before = null): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('check_id', 'severity', 'enforced')
			->selectAlias($qb->func()->count('*'), 'n')
			->from(self::TABLE)
			->groupBy('check_id', 'severity', 'enforced')
			->orderBy('check_id')
			->addOrderBy('severity')
			->addOrderBy('enforced');
		if ($before !== null) {
			$qb->where($qb->expr()->lt('created_at', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT)));
		}
		$result = $qb->executeQuery();
		$counts = [];
		while ($row = $result->fetch()) {
			$key = self::labelKey((string)$row['check_id'], (string)$row['severity'], (bool)$row['enforced']);
			$counts[$key] = ($counts[$key] ?? 0) + (int)$row['n'];
		}
		$result->closeCursor();
		return $counts;
	}

	/**
	 * The key of a check, severity and enforcement in {@see self::countByLabels()}.
	 */
	public static function labelKey(string $checkId, string $severity, bool $enforced): string {
		return $checkId . '|' . $severity . '|' . ($enforced ? '1' : '0');
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
