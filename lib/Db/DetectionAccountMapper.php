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
 * Which accounts each detection is about or mentions (ids_detection_accounts),
 * so that deleting an account and an account's incident report find its
 * detections through an index instead of searching the JSON of every row.
 */
class DetectionAccountMapper {
	public const TABLE = 'ids_detection_accounts';

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * Accounts of a new detection: no row of it can exist yet.
	 *
	 * @param list<string> $uids
	 */
	public function addNew(int $detectionId, array $uids): void {
		MultiRowInsert::insert($this->db, self::TABLE, ['detection_id', 'uid'], array_map(static fn (string $uid): array => [$detectionId, $uid], $uids));
	}

	/**
	 * Accounts of a detection that may have some of them already.
	 *
	 * @param list<string> $uids
	 */
	public function add(int $detectionId, array $uids): void {
		foreach ($uids as $uid) {
			$this->db->insertIgnoreConflict(self::TABLE, ['detection_id' => $detectionId, 'uid' => $uid]);
		}
	}

	/**
	 * @return list<string> the accounts recorded for a detection
	 */
	public function uids(int $detectionId): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('uid')
			->from(self::TABLE)
			->where($qb->expr()->eq('detection_id', $qb->createNamedParameter($detectionId, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$uids = array_map('strval', $result->fetchFirstColumn());
		$result->closeCursor();
		return $uids;
	}

	/**
	 * The detections of an account after an id (and up to another), ascending.
	 *
	 * @return list<int>
	 */
	public function detectionIds(string $uid, int $afterId, int $limit, ?int $upToId = null): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('detection_id')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->gt('detection_id', $qb->createNamedParameter($afterId, IQueryBuilder::PARAM_INT)))
			->orderBy('detection_id', 'ASC')
			->setMaxResults($limit);
		if ($upToId !== null) {
			$qb->andWhere($qb->expr()->lte('detection_id', $qb->createNamedParameter($upToId, IQueryBuilder::PARAM_INT)));
		}
		$result = $qb->executeQuery();
		$ids = array_map('intval', $result->fetchFirstColumn());
		$result->closeCursor();
		return $ids;
	}

	/**
	 * @param ?int $upToId only for the detections up to this one
	 */
	public function deleteForUid(string $uid, ?int $upToId = null): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		if ($upToId !== null) {
			$qb->andWhere($qb->expr()->lte('detection_id', $qb->createNamedParameter($upToId, IQueryBuilder::PARAM_INT)));
		}
		return $qb->executeStatement();
	}

	/**
	 * @param list<int> $detectionIds
	 */
	public function deleteForDetections(array $detectionIds): int {
		if ($detectionIds === []) {
			return 0;
		}
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->in('detection_id', $qb->createNamedParameter($detectionIds, IQueryBuilder::PARAM_INT_ARRAY)));
		return $qb->executeStatement();
	}
}
