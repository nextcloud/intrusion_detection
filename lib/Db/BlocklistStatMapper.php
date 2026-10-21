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
 * Per list and day: how often an address on the list was looked up, and the
 * last addresses that matched.
 */
class BlocklistStatMapper {
	public const TABLE = 'ids_blocklist_stats';
	/** Matched addresses kept per list and day */
	public const SAMPLE_SIZE = 20;

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * Count one match of an address for a list on a day.
	 *
	 * One read and one write. The sample keeps each address once, the most
	 * recent last.
	 */
	public function record(string $listId, string $day, string $ip): void {
		$row = $this->find($listId, $day);
		if ($row === null) {
			$inserted = $this->db->insertIgnoreConflict(self::TABLE, [
				'list_id' => $listId,
				'day' => $day,
				'matches' => 1,
				'sample' => json_encode([$ip]),
			]);
			if ($inserted > 0) {
				return;
			}
			// Another request inserted the row in the meantime.
			$row = $this->find($listId, $day);
			if ($row === null) {
				return;
			}
		}
		$sample = array_values(array_filter($row['sample'], static fn (string $s): bool => $s !== $ip));
		$sample[] = $ip;
		$sample = array_slice($sample, -self::SAMPLE_SIZE);

		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('matches', $qb->createFunction($qb->getColumnName('matches') . ' + 1'))
			->set('sample', $qb->createNamedParameter(json_encode($sample)))
			->where($qb->expr()->eq('id', $qb->createNamedParameter($row['id'], IQueryBuilder::PARAM_INT)));
		$qb->executeStatement();
	}

	/**
	 * @return array{id: int, matches: int, sample: list<string>}|null
	 */
	public function find(string $listId, string $day): ?array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id', 'matches', 'sample')
			->from(self::TABLE)
			->where($qb->expr()->eq('list_id', $qb->createNamedParameter($listId)))
			->andWhere($qb->expr()->eq('day', $qb->createNamedParameter($day)));
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		if (!is_array($row)) {
			return null;
		}
		return ['id' => (int)$row['id'], 'matches' => (int)$row['matches'], 'sample' => self::decodeSample($row['sample'])];
	}

	/**
	 * The counters of the given lists since a day, newest day first.
	 *
	 * @param list<string> $listIds
	 * @return list<array{listId: string, day: string, matches: int, sample: list<string>}>
	 */
	public function findSince(array $listIds, string $sinceDay): array {
		if ($listIds === []) {
			return [];
		}
		$qb = $this->db->getQueryBuilder();
		$qb->select('list_id', 'day', 'matches', 'sample')
			->from(self::TABLE)
			->where($qb->expr()->in('list_id', $qb->createNamedParameter($listIds, IQueryBuilder::PARAM_STR_ARRAY)))
			->andWhere($qb->expr()->gte('day', $qb->createNamedParameter($sinceDay)))
			->orderBy('day', 'DESC')
			->addOrderBy('list_id', 'ASC');
		$result = $qb->executeQuery();
		$rows = [];
		while (($row = $result->fetch()) !== false) {
			$rows[] = [
				'listId' => (string)$row['list_id'],
				'day' => (string)$row['day'],
				'matches' => (int)$row['matches'],
				'sample' => self::decodeSample($row['sample']),
			];
		}
		$result->closeCursor();
		return $rows;
	}

	public function deleteBefore(string $day): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->lt('day', $qb->createNamedParameter($day)));
		return $qb->executeStatement();
	}

	public function deleteList(string $listId): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('list_id', $qb->createNamedParameter($listId)));
		return $qb->executeStatement();
	}

	/**
	 * @return list<string>
	 */
	private static function decodeSample(mixed $json): array {
		$decoded = is_string($json) ? json_decode($json, true) : null;
		return is_array($decoded) ? array_values(array_filter($decoded, 'is_string')) : [];
	}
}
