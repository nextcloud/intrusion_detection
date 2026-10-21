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
 * Which accounts logged in successfully from which address, per hour
 * (ids_logins). Feeds the shared-address safety valve. Kept for 24 hours.
 */
class LoginMapper {
	public const TABLE = 'ids_logins';

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * Record a login; at most one row per address, account and hour.
	 */
	public function record(string $ipKey, string $netKey, string $uid, int $hour): void {
		$this->db->insertIgnoreConflict(self::TABLE, [
			'ip_key' => $ipKey,
			'net_key' => $netKey,
			'uid' => $uid,
			'hour' => $hour,
		]);
	}

	/**
	 * Distinct accounts that logged in from an address since a time.
	 */
	public function distinctUsersForIp(string $ipKey, int $sinceHour): int {
		return $this->distinctUsers('ip_key', $ipKey, $sinceHour);
	}

	/**
	 * Distinct accounts that logged in from a network since a time.
	 */
	public function distinctUsersForNet(string $netKey, int $sinceHour): int {
		return $this->distinctUsers('net_key', $netKey, $sinceHour);
	}

	/**
	 * The most recent logins, newest first (one row per address, account and hour).
	 *
	 * @return list<array{ipKey: string, uid: string}>
	 */
	public function recent(int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('ip_key', 'uid')
			->from(self::TABLE)
			->orderBy('id', 'DESC')
			->setMaxResults($limit);
		$result = $qb->executeQuery();
		$rows = [];
		while (($row = $result->fetch()) !== false) {
			$rows[] = ['ipKey' => (string)$row['ip_key'], 'uid' => (string)$row['uid']];
		}
		$result->closeCursor();
		return $rows;
	}

	public function deleteOlderThan(int $beforeHour): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->lt('hour', $qb->createNamedParameter($beforeHour, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement();
	}

	public function deleteForUser(string $uid): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		return $qb->executeStatement();
	}

	private function distinctUsers(string $column, string $value, int $sinceHour): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->createFunction('COUNT(DISTINCT ' . $qb->getColumnName('uid') . ')'))
			->from(self::TABLE)
			->where($qb->expr()->eq($column, $qb->createNamedParameter($value)))
			->andWhere($qb->expr()->gte('hour', $qb->createNamedParameter($sinceHour, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}
}
