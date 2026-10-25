<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist\Db;

use OCA\IntrusionDetection\Db\IPurges;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

/**
 * Per list and day: how often an address on the list was looked up, and the
 * last addresses that matched. Days are kept RETENTION_DAYS, whether or not
 * the list still syncs.
 */
class BlocklistStatMapper implements IPurges {
	public const TABLE = 'ids_blocklist_stats';
	/** Matched addresses kept per list and day */
	public const SAMPLE_SIZE = 20;
	/** Days of matches are kept this long */
	public const RETENTION_DAYS = 30;

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * Count one match of an address for a list on a day.
	 */
	public function record(string $listId, string $day, string $ip): void {
		$this->add($listId, $day, 1, [$ip]);
	}

	/**
	 * Count matches for a list on a day. One read and one write.
	 *
	 * @param list<string> $ips the addresses that matched, the most recent last
	 */
	public function add(string $listId, string $day, int $matches, array $ips): void {
		$row = $this->find($listId, $day);
		if ($row === null) {
			$inserted = $this->db->insertIgnoreConflict(self::TABLE, [
				'list_id' => $listId,
				'day' => $day,
				'matches' => $matches,
				'sample' => json_encode(self::sample([], $ips)),
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
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('matches', $qb->createFunction($qb->getColumnName('matches') . ' + ' . $qb->createNamedParameter($matches, IQueryBuilder::PARAM_INT)))
			->set('sample', $qb->createNamedParameter(json_encode(self::sample($row['sample'], $ips))))
			->where($qb->expr()->eq('list_id', $qb->createNamedParameter($listId)))
			->andWhere($qb->expr()->eq('day', $qb->createNamedParameter($day)));
		$qb->executeStatement();
	}

	/**
	 * @return array{matches: int, sample: list<string>}|null
	 */
	public function find(string $listId, string $day): ?array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('matches', 'sample')
			->from(self::TABLE)
			->where($qb->expr()->eq('list_id', $qb->createNamedParameter($listId)))
			->andWhere($qb->expr()->eq('day', $qb->createNamedParameter($day)));
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		if (!is_array($row)) {
			return null;
		}
		return ['matches' => (int)$row['matches'], 'sample' => self::decodeSample($row['sample'])];
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

	/**
	 * Delete the days past RETENTION_DAYS.
	 */
	#[\Override]
	public function purge(int $now): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->lt('day', $qb->createNamedParameter(gmdate('Y-m-d', $now - self::RETENTION_DAYS * 86400))));
		return $qb->executeStatement();
	}

	public function deleteList(string $listId): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('list_id', $qb->createNamedParameter($listId)));
		return $qb->executeStatement();
	}

	/**
	 * The sample with the new addresses: each address once, the most recent
	 * last, at most SAMPLE_SIZE.
	 *
	 * @param list<string> $sample
	 * @param list<string> $ips
	 * @return list<string>
	 */
	private static function sample(array $sample, array $ips): array {
		$sample = array_values(array_filter($sample, static fn (string $s): bool => !in_array($s, $ips, true)));
		return array_slice([...$sample, ...array_values(array_unique($ips))], -self::SAMPLE_SIZE);
	}

	/**
	 * @return list<string>
	 */
	private static function decodeSample(mixed $json): array {
		$decoded = is_string($json) ? json_decode($json, true) : null;
		return is_array($decoded) ? array_values(array_filter($decoded, 'is_string')) : [];
	}
}
