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
 * The networks users confirmed as their own (ids_trusted_networks), one row
 * per account and network.
 */
class TrustedNetworkMapper {
	public const TABLE = 'ids_trusted_networks';

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * Trust a network until a time, or move an existing entry to that time.
	 */
	public function trust(string $uid, string $netKey, ?int $detectionId, int $now, int $expiresAt): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('expires_at', $qb->createNamedParameter($expiresAt, IQueryBuilder::PARAM_INT))
			->set('created_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))
			->set('detection_id', $qb->createNamedParameter($detectionId, $detectionId === null ? IQueryBuilder::PARAM_NULL : IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->eq('net_key', $qb->createNamedParameter($netKey)));
		if ($qb->executeStatement() > 0) {
			return;
		}
		$this->db->insertIgnoreConflict(self::TABLE, [
			'uid' => $uid,
			'net_key' => $netKey,
			'created_at' => $now,
			'expires_at' => $expiresAt,
			'detection_id' => $detectionId,
		]);
	}

	public function isTrusted(string $uid, string $netKey, int $now): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->eq('net_key', $qb->createNamedParameter($netKey)))
			->andWhere($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)))
			->setMaxResults(1);
		$result = $qb->executeQuery();
		$found = $result->fetchOne() !== false;
		$result->closeCursor();
		return $found;
	}

	/**
	 * @return list<array{id: int, net_key: string, created_at: int, expires_at: int, detection_id: ?int}> the account's active entries, newest first
	 */
	public function findActive(string $uid, int $now, int $limit = 100): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id', 'net_key', 'created_at', 'expires_at', 'detection_id')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)))
			->orderBy('created_at', 'DESC')
			->addOrderBy('id', 'DESC')
			->setMaxResults($limit);
		$result = $qb->executeQuery();
		$rows = [];
		while ($row = $result->fetch()) {
			$rows[] = [
				'id' => (int)$row['id'],
				'net_key' => (string)$row['net_key'],
				'created_at' => (int)$row['created_at'],
				'expires_at' => (int)$row['expires_at'],
				'detection_id' => $row['detection_id'] === null ? null : (int)$row['detection_id'],
			];
		}
		$result->closeCursor();
		return $rows;
	}

	/**
	 * @return ?string the network of the account's entry, null when the account has no such entry
	 */
	public function delete(string $uid, int $id): ?string {
		$qb = $this->db->getQueryBuilder();
		$qb->select('net_key')
			->from(self::TABLE)
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		$result = $qb->executeQuery();
		$netKey = $result->fetchOne();
		$result->closeCursor();
		if ($netKey === false) {
			return null;
		}
		$delete = $this->db->getQueryBuilder();
		$delete->delete(self::TABLE)
			->where($delete->expr()->eq('id', $delete->createNamedParameter($id, IQueryBuilder::PARAM_INT)))
			->andWhere($delete->expr()->eq('uid', $delete->createNamedParameter($uid)))
			->executeStatement();
		return (string)$netKey;
	}

	public function deleteNetwork(string $uid, string $netKey): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->eq('net_key', $qb->createNamedParameter($netKey)));
		return $qb->executeStatement() > 0;
	}

	public function deleteExpired(int $now): int {
		return BatchedDelete::run($this->db, self::TABLE, 'id', static fn (IQueryBuilder $qb): IQueryBuilder => $qb->where($qb->expr()->lte('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))));
	}
}
