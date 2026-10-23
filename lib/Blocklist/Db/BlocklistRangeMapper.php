<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist\Db;

use OCA\IntrusionDetection\Db\MultiRowInsert;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;
use OCP\Snowflake\ISnowflakeGenerator;

/**
 * The ranges of the downloaded lists. Rows are plain arrays, not entities:
 * a list can have hundreds of thousands of them.
 *
 * Each sync writes a complete new version of a list. Readers ask for one
 * version only, so they see either the old or the new list, never a mix.
 */
class BlocklistRangeMapper {
	public const TABLE = 'ids_blocklist_ranges';
	/** Rows inserted per transaction */
	private const CHUNK = 5000;

	public function __construct(
		private readonly IDBConnection $db,
		private readonly ISnowflakeGenerator $snowflakes,
	) {
	}

	/**
	 * The range of one list version that contains the address, if any.
	 *
	 * The ranges of a version never overlap (they are merged when written),
	 * so the last range starting at or below the address is the only candidate.
	 *
	 * @return array{start: string, end: string}|null
	 */
	public function findContaining(string $listId, int $version, int $family, string $addressHex): ?array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('range_start', 'range_end')
			->from(self::TABLE)
			->where($qb->expr()->eq('list_id', $qb->createNamedParameter($listId)))
			->andWhere($qb->expr()->eq('version', $qb->createNamedParameter($version, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('family', $qb->createNamedParameter($family, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lte('range_start', $qb->createNamedParameter($addressHex)))
			->orderBy('range_start', 'DESC')
			->setMaxResults(1);
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		if (!is_array($row) || strcmp((string)$row['range_end'], $addressHex) < 0) {
			return null;
		}
		return ['start' => (string)$row['range_start'], 'end' => (string)$row['range_end']];
	}

	/**
	 * The range of a list version that starts last at or before an address,
	 * whether or not it contains the address. Ranges of one version never
	 * overlap ({@see \OCA\IntrusionDetection\Net\RangeCodec::merge()}), so
	 * it is the only one that can reach the address or anything after it.
	 *
	 * @return ?array{start: string, end: string}
	 */
	public function findLastStartingAtOrBefore(string $listId, int $version, int $family, string $addressHex): ?array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('range_start', 'range_end')
			->from(self::TABLE)
			->where($qb->expr()->eq('list_id', $qb->createNamedParameter($listId)))
			->andWhere($qb->expr()->eq('version', $qb->createNamedParameter($version, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('family', $qb->createNamedParameter($family, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lte('range_start', $qb->createNamedParameter($addressHex)))
			->orderBy('range_start', 'DESC')
			->setMaxResults(1);
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		return is_array($row) ? ['start' => (string)$row['range_start'], 'end' => (string)$row['range_end']] : null;
	}

	/**
	 * Write a version of a list, with multi-row inserts in transactions of
	 * CHUNK rows. Leftovers of the same version (from a sync that died
	 * half-way) are removed first.
	 *
	 * @param list<string> $ranges compact ranges ({@see RangeCodec})
	 */
	public function writeVersion(string $listId, int $version, array $ranges): void {
		$this->deleteVersion($listId, $version);
		foreach (array_chunk($ranges, self::CHUNK) as $chunk) {
			$rows = array_map(fn (string $range): array => [
				$this->snowflakes->nextId(),
				$listId,
				$version,
				(int)$range[0],
				substr($range, 1, RangeCodec::HEX_LENGTH),
				substr($range, 1 + RangeCodec::HEX_LENGTH, RangeCodec::HEX_LENGTH),
			], $chunk);
			$this->db->beginTransaction();
			try {
				MultiRowInsert::insert($this->db, self::TABLE, ['id', 'list_id', 'version', 'family', 'range_start', 'range_end'], $rows);
				$this->db->commit();
			} catch (\Throwable $e) {
				$this->db->rollBack();
				throw $e;
			}
		}
	}

	public function deleteVersion(string $listId, int $version): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('list_id', $qb->createNamedParameter($listId)))
			->andWhere($qb->expr()->eq('version', $qb->createNamedParameter($version, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement();
	}

	/**
	 * Delete every version of a list except the given ones.
	 *
	 * @param list<int> $keep
	 */
	public function deleteVersionsExcept(string $listId, array $keep): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('list_id', $qb->createNamedParameter($listId)));
		if ($keep !== []) {
			$qb->andWhere($qb->expr()->notIn('version', $qb->createNamedParameter($keep, IQueryBuilder::PARAM_INT_ARRAY)));
		}
		return $qb->executeStatement();
	}

	/**
	 * The highest version written for a list, complete or not; 0 if none.
	 */
	public function maxVersion(string $listId): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->max('version'))
			->from(self::TABLE)
			->where($qb->expr()->eq('list_id', $qb->createNamedParameter($listId)));
		$result = $qb->executeQuery();
		$max = (int)$result->fetchOne();
		$result->closeCursor();
		return $max;
	}

	/**
	 * The lists that have rows, for cleaning up lists that were switched off or removed.
	 *
	 * @return list<string>
	 */
	public function listIds(): array {
		$qb = $this->db->getQueryBuilder();
		$qb->selectDistinct('list_id')->from(self::TABLE);
		$result = $qb->executeQuery();
		$ids = [];
		while (($id = $result->fetchOne()) !== false) {
			$ids[] = (string)$id;
		}
		$result->closeCursor();
		return $ids;
	}

	public function countVersion(string $listId, int $version): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*'))
			->from(self::TABLE)
			->where($qb->expr()->eq('list_id', $qb->createNamedParameter($listId)))
			->andWhere($qb->expr()->eq('version', $qb->createNamedParameter($version, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}
}
