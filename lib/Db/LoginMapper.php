<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;
use OCP\Snowflake\ISnowflakeGenerator;

/**
 * Which accounts logged in successfully from which address, per hour
 * (ids_logins). Feeds the shared-address safety valve. Kept for 24 hours.
 */
class LoginMapper implements IPurges {
	public const TABLE = 'ids_logins';
	/** Logins are kept this long, as far back as the safety valve looks */
	public const RETENTION = 86400;

	public function __construct(
		private readonly IDBConnection $db,
		private readonly ISnowflakeGenerator $snowflakes,
	) {
	}

	/**
	 * Record a login; at most one row per address, account and hour.
	 */
	public function record(string $ipKey, string $netKey, string $uid, int $hour): void {
		$this->db->insertIgnoreConflict(self::TABLE, [
			'id' => $this->snowflakes->nextId(),
			'ip_key' => $ipKey,
			'net_key' => $netKey,
			'uid' => $uid,
			'hour' => $hour,
		]);
	}

	/**
	 * Whether the login of the account from the address in the hour is recorded.
	 */
	public function exists(string $ipKey, string $uid, int $hour): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id')
			->from(self::TABLE)
			->where($qb->expr()->eq('ip_key', $qb->createNamedParameter($ipKey)))
			->andWhere($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->eq('hour', $qb->createNamedParameter($hour, IQueryBuilder::PARAM_INT)))
			->setMaxResults(1);
		$result = $qb->executeQuery();
		$found = $result->fetchOne() !== false;
		$result->closeCursor();
		return $found;
	}

	/**
	 * The distinct accounts that logged in from an address since a time, at most `$limit`.
	 *
	 * @return list<string>
	 */
	public function distinctUidsForIp(string $ipKey, int $sinceHour, int $limit): array {
		return $this->distinctUids(new KeyMatch([$ipKey]), 'ip_key', $sinceHour, $limit);
	}

	/**
	 * The distinct accounts that logged in from any of a set of networks since a time, at most `$limit`.
	 *
	 * @return list<string>
	 */
	public function distinctUidsForNets(KeyMatch $netKeys, int $sinceHour, int $limit): array {
		return $this->distinctUids($netKeys, 'net_key', $sinceHour, $limit);
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

	#[\Override]
	public function purge(int $now): int {
		return $this->deleteOlderThan(intdiv($now - self::RETENTION, 3600));
	}

	public function deleteOlderThan(int $beforeHour): int {
		return BatchedDelete::run($this->db, self::TABLE, 'id', 'hour', static fn (IQueryBuilder $qb): IQueryBuilder => $qb->where($qb->expr()->lt('hour', $qb->createNamedParameter($beforeHour, IQueryBuilder::PARAM_INT))));
	}

	public function deleteForUser(string $uid): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		return $qb->executeStatement();
	}

	/**
	 * @param 'ip_key'|'net_key' $column
	 * @return list<string>
	 */
	private function distinctUids(KeyMatch $keys, string $column, int $sinceHour, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->selectDistinct('uid')
			->from(self::TABLE)
			->where($keys->condition($qb, $column))
			->andWhere($qb->expr()->gte('hour', $qb->createNamedParameter($sinceHour, IQueryBuilder::PARAM_INT)))
			->setMaxResults($limit);
		$result = $qb->executeQuery();
		$uids = array_map('strval', $result->fetchFirstColumn());
		$result->closeCursor();
		return $uids;
	}
}
