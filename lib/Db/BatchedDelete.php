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
 */
final class BatchedDelete {
	public const BATCH = 1000;
	public const MAX_BATCHES = 100;

	/**
	 * @param string $idColumn the single-column primary key
	 * @param \Closure(IQueryBuilder): mixed $where adds the condition to a query on the table
	 * @param IQueryBuilder::PARAM_INT_ARRAY|IQueryBuilder::PARAM_STR_ARRAY $idType
	 * @param ?\Closure(list<int|string>): void $beforeDelete runs with the ids of each batch before it is deleted, e.g. to delete dependent rows
	 * @return int how many rows were deleted
	 */
	public static function run(
		IDBConnection $db,
		string $table,
		string $idColumn,
		\Closure $where,
		int $idType = IQueryBuilder::PARAM_INT_ARRAY,
		int $batch = self::BATCH,
		int $maxBatches = self::MAX_BATCHES,
		?\Closure $beforeDelete = null,
	): int {
		$deleted = 0;
		for ($i = 0; $i < $maxBatches; $i++) {
			$select = $db->getQueryBuilder();
			$select->select($idColumn)->from($table)->setMaxResults($batch);
			$where($select);
			$result = $select->executeQuery();
			$ids = $result->fetchFirstColumn();
			$result->closeCursor();
			if ($ids === []) {
				break;
			}
			$ids = $idType === IQueryBuilder::PARAM_INT_ARRAY ? array_map('intval', $ids) : array_map('strval', $ids);
			if ($beforeDelete !== null) {
				$beforeDelete($ids);
			}
			$delete = $db->getQueryBuilder();
			$delete->delete($table)
				->where($delete->expr()->in($idColumn, $delete->createNamedParameter($ids, $idType)));
			$deleted += $delete->executeStatement();
			if (count($ids) < $batch) {
				break;
			}
		}
		return $deleted;
	}
}
