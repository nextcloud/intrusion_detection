<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\State;

use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

/**
 * The internal state of the app, in ids_state (one row per name): what the
 * app records for itself, such as the last digest sent or the progress of a
 * cleanup, and the last period claimed by a task that runs once for all web
 * servers. Each name is declared by the class that owns it.
 *
 * Kept out of the app config, because every app config write drops core's
 * cached app config of the web server, and because these values are only
 * read where they are needed, never on every request. Every read goes to
 * the database, so a long-running process sees what others wrote. The few
 * small values requests read often are in {@see HotState}.
 */
class AppState {
	public const TABLE = 'ids_state';
	/** When the app was first installed; 0 before */
	public const INSTALLED_AT = 'installed_at';
	/** A claimed period is stored zero-padded to this length, so that periods compare as strings */
	private const PERIOD_DIGITS = 20;

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

	public function delete(string $name): void {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('name', $qb->createNamedParameter($name)));
		$qb->executeStatement();
	}

	/**
	 * The rows whose name starts with a prefix.
	 *
	 * @return array<string, string> value by the rest of the name
	 */
	public function getPrefixed(string $prefix): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('name', 'value')
			->from(self::TABLE)
			->where($qb->expr()->like('name', $qb->createNamedParameter($this->db->escapeLikeParameter($prefix) . '%')));
		$result = $qb->executeQuery();
		$rows = [];
		while (($row = $result->fetch()) !== false) {
			$rows[substr((string)$row['name'], strlen($prefix))] = (string)$row['value'];
		}
		$result->closeCursor();
		return $rows;
	}

	/**
	 * @param list<string> $names
	 */
	public function deleteNames(array $names): int {
		$deleted = 0;
		foreach (array_chunk($names, 1000) as $chunk) {
			$qb = $this->db->getQueryBuilder();
			$qb->delete(self::TABLE)
				->where($qb->expr()->in('name', $qb->createNamedParameter($chunk, IQueryBuilder::PARAM_STR_ARRAY)));
			$deleted += $qb->executeStatement();
		}
		return $deleted;
	}

	/**
	 * A stored number; 0 when there is none.
	 */
	public function getInt(string $name): int {
		return (int)($this->get($name) ?? 0);
	}

	public function setInt(string $name, int $value): void {
		$this->set($name, (string)$value);
	}

	/**
	 * Claims one period of a recurring task for a single caller on all web
	 * servers: true for the first caller of `$period` (a number that grows,
	 * such as the time divided by the interval), false for every later
	 * caller of it or of an earlier period. One conditional update decides,
	 * so two web servers never both win.
	 */
	public function claim(string $name, int $period): bool {
		$value = sprintf('%0' . self::PERIOD_DIGITS . 'd', $period);
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('value', $qb->createNamedParameter($value))
			->where($qb->expr()->eq('name', $qb->createNamedParameter($name)))
			->andWhere($qb->expr()->lt($qb->expr()->castColumn('value', IQueryBuilder::PARAM_STR), $qb->createNamedParameter($value)));
		if ($qb->executeStatement() > 0) {
			return true;
		}
		return $this->db->insertIgnoreConflict(self::TABLE, ['name' => $name, 'value' => $value]) > 0;
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
