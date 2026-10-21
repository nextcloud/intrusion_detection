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
 * Read-only aggregates for the admin digest. Every query covers one period
 * on the indexed `created_at` column and returns a bounded number of rows.
 */
class DigestMapper {
	/** Detections read at most per list that is aggregated in PHP */
	public const MAX_ROWS = 500;

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * The addresses with the most detections in the period.
	 *
	 * @return list<array{ip: string, detections: int}>
	 */
	public function topSources(int $since, int $until, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('ip')
			->selectAlias($qb->func()->count('*'), 'n')
			->from(DetectionMapper::TABLE)
			->where($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lt('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->isNotNull('ip'))
			->groupBy('ip')
			->orderBy($qb->func()->count('*'), 'DESC')
			->addOrderBy('ip', 'ASC')
			->setMaxResults($limit);
		$rows = [];
		$result = $qb->executeQuery();
		while ($row = $result->fetch()) {
			$rows[] = ['ip' => (string)$row['ip'], 'detections' => (int)$row['n']];
		}
		$result->closeCursor();
		return $rows;
	}

	/**
	 * Which checks fired for these addresses in the period, most frequent first.
	 *
	 * @param list<string> $ips
	 * @return array<string, list<string>> check ids by address
	 */
	public function checksForSources(array $ips, int $since, int $until): array {
		if ($ips === []) {
			return [];
		}
		$qb = $this->db->getQueryBuilder();
		$qb->select('ip', 'check_id')
			->selectAlias($qb->func()->count('*'), 'n')
			->from(DetectionMapper::TABLE)
			->where($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lt('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->in('ip', $qb->createNamedParameter($ips, IQueryBuilder::PARAM_STR_ARRAY)))
			->groupBy('ip', 'check_id');
		$counts = [];
		$result = $qb->executeQuery();
		while ($row = $result->fetch()) {
			$counts[(string)$row['ip']][(string)$row['check_id']] = (int)$row['n'];
		}
		$result->closeCursor();
		$checks = [];
		foreach ($counts as $ip => $byCheck) {
			arsort($byCheck);
			$checks[$ip] = array_map('strval', array_keys($byCheck));
		}
		return $checks;
	}

	/**
	 * Blocks created in the period because of detections from these addresses.
	 *
	 * A block created in the period also ends after its start, so the
	 * condition on `expires_at` lets the expiry index narrow the scan.
	 *
	 * @param list<string> $ips
	 * @return array<string, int> by address
	 */
	public function bansForSources(array $ips, int $since, int $until): array {
		if ($ips === []) {
			return [];
		}
		$qb = $this->db->getQueryBuilder();
		$qb->select('d.ip')
			->selectAlias($qb->func()->count('b.id'), 'n')
			->from(BanMapper::TABLE, 'b')
			->innerJoin('b', DetectionMapper::TABLE, 'd', $qb->expr()->eq('d.id', 'b.detection_id'))
			->where($qb->expr()->gte('b.expires_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->gte('b.created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lt('b.created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->in('d.ip', $qb->createNamedParameter($ips, IQueryBuilder::PARAM_STR_ARRAY)))
			->groupBy('d.ip');
		$bans = [];
		$result = $qb->executeQuery();
		while ($row = $result->fetch()) {
			$bans[(string)$row['ip']] = (int)$row['n'];
		}
		$result->closeCursor();
		return $bans;
	}

	/**
	 * Blocks created in the period, by a check or by hand.
	 */
	public function bansCreated(int $since, int $until): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*', 'n'))
			->from(BanMapper::TABLE)
			->where($qb->expr()->gte('expires_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lt('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	/**
	 * Detections of one check per account in the period, most first.
	 *
	 * @return list<array{uid: string, detections: int}>
	 */
	public function accountsForCheck(string $checkId, int $since, int $until, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('uid')
			->selectAlias($qb->func()->count('*'), 'n')
			->from(DetectionMapper::TABLE)
			->where($qb->expr()->eq('check_id', $qb->createNamedParameter($checkId)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lt('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->isNotNull('uid'))
			->groupBy('uid')
			->orderBy($qb->func()->count('*'), 'DESC')
			->addOrderBy('uid', 'ASC')
			->setMaxResults($limit);
		$rows = [];
		$result = $qb->executeQuery();
		while ($row = $result->fetch()) {
			$rows[] = ['uid' => (string)$row['uid'], 'detections' => (int)$row['n']];
		}
		$result->closeCursor();
		return $rows;
	}

	/**
	 * Detections of one check per share in the period, most first.
	 *
	 * @return list<array{shareId: int, owner: ?string, detections: int}>
	 */
	public function sharesForCheck(string $checkId, int $since, int $until, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('share_id')
			->selectAlias($qb->func()->max('uid'), 'owner')
			->selectAlias($qb->func()->count('*'), 'n')
			->from(DetectionMapper::TABLE)
			->where($qb->expr()->eq('check_id', $qb->createNamedParameter($checkId)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lt('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->isNotNull('share_id'))
			->groupBy('share_id')
			->orderBy($qb->func()->count('*'), 'DESC')
			->addOrderBy('share_id', 'ASC')
			->setMaxResults($limit);
		$rows = [];
		$result = $qb->executeQuery();
		while ($row = $result->fetch()) {
			$rows[] = [
				'shareId' => (int)$row['share_id'],
				'owner' => $row['owner'] === null ? null : (string)$row['owner'],
				'detections' => (int)$row['n'],
			];
		}
		$result->closeCursor();
		return $rows;
	}

	/**
	 * The detections of one check in the period, newest first, at most MAX_ROWS.
	 *
	 * @return list<Detection>
	 */
	public function detectionsOfCheck(string $checkId, int $since, int $until): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(DetectionMapper::TABLE)
			->where($qb->expr()->eq('check_id', $qb->createNamedParameter($checkId)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lt('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->orderBy('created_at', 'DESC')
			->setMaxResults(self::MAX_ROWS);
		$detections = [];
		$result = $qb->executeQuery();
		while ($row = $result->fetch()) {
			$detections[] = Detection::fromRow($row);
		}
		$result->closeCursor();
		return $detections;
	}

	/**
	 * Detections that their account answered with "This was not me" in the
	 * period. Only detections of the last `$lookback` seconds before the
	 * period are considered, as long as they can be answered.
	 *
	 * @return list<array{id: int, uid: string, checkId: string, verdictAt: int}> newest answer first
	 */
	public function deniedByUsers(int $since, int $until, int $lookback, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id', 'uid', 'check_id', 'verdict_at')
			->from(DetectionMapper::TABLE)
			->where($qb->expr()->gte('created_at', $qb->createNamedParameter($since - $lookback, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('user_verdict', $qb->createNamedParameter(Detection::VERDICT_DENIED)))
			->andWhere($qb->expr()->gte('verdict_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lt('verdict_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->isNotNull('uid'))
			->orderBy('verdict_at', 'DESC')
			->setMaxResults($limit);
		$rows = [];
		$result = $qb->executeQuery();
		while ($row = $result->fetch()) {
			$rows[] = [
				'id' => (int)$row['id'],
				'uid' => (string)$row['uid'],
				'checkId' => (string)$row['check_id'],
				'verdictAt' => (int)$row['verdict_at'],
			];
		}
		$result->closeCursor();
		return $rows;
	}
}
