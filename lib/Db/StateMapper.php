<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCP\IDBConnection;

/**
 * Internal state the app writes often (ids_state, one row per name): the
 * cache version of the address verdicts, the state of the firewall export.
 * Kept out of the app config, because every app config write drops core's
 * cached app config of the web server, and because these values are only
 * read where they are needed, never on every request.
 */
class StateMapper {
	public const TABLE = 'ids_state';

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	public function get(string $name): ?string {
		$qb = $this->db->getQueryBuilder();
		$qb->select('value')
			->from(self::TABLE)
			->where($qb->expr()->eq('name', $qb->createNamedParameter($name)));
		$result = $qb->executeQuery();
		$value = $result->fetchOne();
		$result->closeCursor();
		return is_string($value) ? $value : null;
	}

	public function set(string $name, string $value): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('value', $qb->createNamedParameter($value))
			->where($qb->expr()->eq('name', $qb->createNamedParameter($name)));
		if ($qb->executeStatement() > 0) {
			return;
		}
		// A missing row, or (on MySQL) an unchanged value; another request may insert it meanwhile.
		$this->db->insertIgnoreConflict(self::TABLE, ['name' => $name, 'value' => $value]);
	}

	/**
	 * @return array<array-key, mixed>
	 */
	public function getJson(string $name): array {
		$decoded = json_decode($this->get($name) ?? '', true);
		return is_array($decoded) ? $decoded : [];
	}

	/**
	 * @param array<array-key, mixed> $value
	 */
	public function setJson(string $name, array $value): void {
		$this->set($name, json_encode($value, JSON_THROW_ON_ERROR));
	}
}
