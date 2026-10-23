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
 * Deletes the rows that match a condition a batch at a time: the ids are
 * selected through the condition's index, then deleted by primary key. No
 * statement locks or scans more than one batch, so a large backlog cannot
 * stall the other writers of a table, and a run stops after `$maxBatches`.
 *
 * The batches are read in the order of an indexed column of the condition
 * and the id, each one from where the last one ended (keyset paging): a
 * batch never walks the rows, or the dead index entries, that earlier
 * batches deleted.
 */
final class BatchedDelete {
	public const BATCH = 1000;
	public const MAX_BATCHES = 100;

	/**
	 * @param string $idColumn the single-column primary key
	 * @param string $orderColumn an integer column of the condition that an index starts with (after the condition's equality columns)
	 * @param \Closure(IQueryBuilder): mixed $where adds the condition to a query on the table
	 * @param IQueryBuilder::PARAM_INT_ARRAY|IQueryBuilder::PARAM_STR_ARRAY $idType
	 * @param ?\Closure(list<int|string>): void $beforeDelete runs with the ids of each batch before it is deleted, e.g. to delete dependent rows
	 * @return int how many rows were deleted
	 */
	public static function run(
		IDBConnection $db,
		string $table,
		string $idColumn,
		string $orderColumn,
		\Closure $where,
		int $idType = IQueryBuilder::PARAM_STR_ARRAY,
		int $batch = self::BATCH,
		int $maxBatches = self::MAX_BATCHES,
		?\Closure $beforeDelete = null,
	): int {
		$deleted = 0;
		foreach (self::batches($db, $table, $idColumn, $orderColumn, $where, $idType, $batch, $maxBatches) as $ids) {
			if ($beforeDelete !== null) {
				$beforeDelete($ids);
			}
			$delete = $db->getQueryBuilder();
			$delete->delete($table)
				->where($delete->expr()->in($idColumn, $delete->createNamedParameter($ids, $idType)));
			$deleted += $delete->executeStatement();
		}
		return $deleted;
	}

	/**
	 * The ids of the rows that match, a batch at a time, in the order of
	 * `$orderColumn` and the id. The caller may change or delete each batch
	 * before it asks for the next one.
	 *
	 * @param \Closure(IQueryBuilder): mixed $where adds the condition to a query on the table
	 * @param IQueryBuilder::PARAM_INT_ARRAY|IQueryBuilder::PARAM_STR_ARRAY $idType
	 * @return \Generator<int, list<int|string>>
	 */
	public static function batches(
		IDBConnection $db,
		string $table,
		string $idColumn,
		string $orderColumn,
		\Closure $where,
		int $idType = IQueryBuilder::PARAM_STR_ARRAY,
		int $batch = self::BATCH,
		int $maxBatches = self::MAX_BATCHES,
	): \Generator {
		$ints = $idType === IQueryBuilder::PARAM_INT_ARRAY;
		$after = null;
		for ($i = 0; $i < $maxBatches; $i++) {
			$select = $db->getQueryBuilder();
			$select->select($idColumn, $orderColumn)
				->from($table)
				->orderBy($orderColumn, 'ASC')
				->addOrderBy($idColumn, 'ASC')
				->setMaxResults($batch);
			$where($select);
			if ($after !== null) {
				[$lastOrder, $lastId] = $after;
				// The lower bound lets PostgreSQL start the index scan there; the ranges
				// after it let MySQL read the index in order instead of sorting.
				$select->andWhere($select->expr()->gte($orderColumn, $select->createNamedParameter($lastOrder, IQueryBuilder::PARAM_INT)))
					->andWhere($select->expr()->orX(
						$select->expr()->gt($orderColumn, $select->createNamedParameter($lastOrder, IQueryBuilder::PARAM_INT)),
						$select->expr()->andX(
							$select->expr()->eq($orderColumn, $select->createNamedParameter($lastOrder, IQueryBuilder::PARAM_INT)),
							$select->expr()->gt($idColumn, $select->createNamedParameter($lastId, $ints ? IQueryBuilder::PARAM_INT : IQueryBuilder::PARAM_STR)),
						),
					));
			}
			$result = $select->executeQuery();
			$rows = $result->fetchAll();
			$result->closeCursor();
			if ($rows === []) {
				return;
			}
			$ids = array_map(static fn (array $row): int|string => $ints ? (int)$row[$idColumn] : (string)$row[$idColumn], $rows);
			yield $ids;
			$last = end($rows);
			$after = [(int)$last[$orderColumn], $ints ? (int)$last[$idColumn] : (string)$last[$idColumn]];
			if (count($rows) < $batch) {
				return;
			}
		}
	}
}
