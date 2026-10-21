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
 * The last seen state of the watched settings (ids_config_snapshot): a keyed
 * hash per setting, and the display value of settings that are not secret.
 */
class ConfigSnapshotMapper {
	public const TABLE = 'ids_config_snapshot';

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * @return array<string, array{hash: string, display: ?string, updated_at: int}> keyed by setting key
	 */
	public function all(): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('setting_key', 'value_hash', 'display_value', 'updated_at')
			->from(self::TABLE);
		$result = $qb->executeQuery();
		$rows = [];
		while ($row = $result->fetch()) {
			$rows[(string)$row['setting_key']] = [
				'hash' => (string)$row['value_hash'],
				'display' => $row['display_value'] === null ? null : (string)$row['display_value'],
				'updated_at' => (int)$row['updated_at'],
			];
		}
		$result->closeCursor();
		return $rows;
	}

	/**
	 * @return ?array{hash: string, display: ?string, updated_at: int}
	 */
	public function find(string $key): ?array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('value_hash', 'display_value', 'updated_at')
			->from(self::TABLE)
			->where($qb->expr()->eq('setting_key', $qb->createNamedParameter($key)));
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		if ($row === false) {
			return null;
		}
		return [
			'hash' => (string)$row['value_hash'],
			'display' => $row['display_value'] === null ? null : (string)$row['display_value'],
			'updated_at' => (int)$row['updated_at'],
		];
	}

	/**
	 * Insert or update one setting's row.
	 */
	public function store(string $key, string $hash, ?string $display, int $now): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('value_hash', $qb->createNamedParameter($hash))
			->set('display_value', $qb->createNamedParameter($display))
			->set('updated_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('setting_key', $qb->createNamedParameter($key)));
		if ($qb->executeStatement() > 0) {
			return;
		}
		$this->db->insertIgnoreConflict(self::TABLE, [
			'setting_key' => $key,
			'value_hash' => $hash,
			'display_value' => $display,
			'updated_at' => $now,
		]);
	}

	public function delete(string $key): void {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('setting_key', $qb->createNamedParameter($key)))
			->executeStatement();
	}

	public function deleteAll(): void {
		$this->db->getQueryBuilder()->delete(self::TABLE)->executeStatement();
	}
}
