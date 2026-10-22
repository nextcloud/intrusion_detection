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
 * Internal state the app writes often (ids_state, one row per name): the
 * cache version of the address verdicts, the state of the firewall export,
 * the last period claimed by a task that runs once for all web servers.
 * Kept out of the app config, because every app config write drops core's
 * cached app config of the web server, and because these values are only
 * read where they are needed, never on every request.
 */
class StateMapper {
	public const TABLE = 'ids_state';
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
