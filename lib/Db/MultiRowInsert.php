<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCP\IDBConnection;

/**
 * Inserts many rows with one statement per chunk instead of one per row.
 * Oracle has no multi-row VALUES, so rows are inserted one by one there.
 * The rows must not conflict with existing ones: a conflict fails the chunk.
 */
final class MultiRowInsert {
	/** Bound parameters per statement; SQLite builds without a raised limit allow 999 */
	private const MAX_PARAMS_SQLITE = 999;
	private const MAX_ROWS = 1000;

	/**
	 * @param list<string> $columns
	 * @param list<list<int|string|null>> $rows values in the order of `$columns`
	 * @return int how many rows were inserted
	 */
	public static function insert(IDBConnection $db, string $table, array $columns, array $rows): int {
		if ($rows === []) {
			return 0;
		}
		$provider = $db->getDatabaseProvider();
		$perStatement = match ($provider) {
			IDBConnection::PLATFORM_ORACLE => 1,
			IDBConnection::PLATFORM_SQLITE => max(1, intdiv(self::MAX_PARAMS_SQLITE, count($columns))),
			default => self::MAX_ROWS,
		};
		$head = 'INSERT INTO `*PREFIX*' . $table . '` (' . implode(', ', array_map(static fn (string $c): string => '`' . $c . '`', $columns)) . ') VALUES ';
		$placeholders = '(' . implode(', ', array_fill(0, count($columns), '?')) . ')';
		$inserted = 0;
		foreach (array_chunk($rows, $perStatement) as $chunk) {
			$params = [];
			foreach ($chunk as $row) {
				foreach ($row as $value) {
					$params[] = $value;
				}
			}
			$inserted += $db->executeStatement($head . implode(', ', array_fill(0, count($chunk), $placeholders)), $params);
		}
		return $inserted;
	}
}
