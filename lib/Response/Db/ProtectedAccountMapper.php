<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response\Db;

use OCA\IntrusionDetection\Db\BatchedDelete;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

/**
 * Accounts under extra protection (ids_protected_accounts), one row per
 * account, keyed by uid.
 */
class ProtectedAccountMapper {
	public const TABLE = 'ids_protected_accounts';

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * Protect an account until a time, or extend a protection that would end
	 * earlier. A protection that already lasts longer stays as it is.
	 */
	public function protect(string $uid, string $reason, ?string $detectionId, int $now, int $expiresAt): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('expires_at', $qb->createNamedParameter($expiresAt, IQueryBuilder::PARAM_INT))
			->set('reason', $qb->createNamedParameter($reason))
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->lt('expires_at', $qb->createNamedParameter($expiresAt, IQueryBuilder::PARAM_INT)));
		if ($detectionId !== null) {
			$qb->set('detection_id', $qb->createNamedParameter($detectionId));
		}
		if ($qb->executeStatement() > 0) {
			return;
		}
		$this->db->insertIgnoreConflict(self::TABLE, [
			'uid' => $uid,
			'reason' => $reason,
			'detection_id' => $detectionId,
			'created_at' => $now,
			'expires_at' => $expiresAt,
		]);
	}

	/**
	 * @return ?array{uid: string, reason: string, detection_id: ?string, created_at: int, expires_at: int}
	 */
	public function find(string $uid): ?array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('uid', 'reason', 'detection_id', 'created_at', 'expires_at')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		return $row === false ? null : self::row($row);
	}

	/**
	 * @return list<array{uid: string, reason: string, detection_id: ?string, created_at: int, expires_at: int}> active protections, ending soonest first
	 */
	public function findActive(int $now, int $limit = 200): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('uid', 'reason', 'detection_id', 'created_at', 'expires_at')
			->from(self::TABLE)
			->where($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)))
			->orderBy('expires_at', 'ASC')
			->setMaxResults($limit);
		$result = $qb->executeQuery();
		$rows = [];
		while ($row = $result->fetch()) {
			$rows[] = self::row($row);
		}
		$result->closeCursor();
		return $rows;
	}

	public function delete(string $uid): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		return $qb->executeStatement() > 0;
	}

	public function deleteExpired(int $now): int {
		return BatchedDelete::run($this->db, self::TABLE, 'uid', 'expires_at', static fn (IQueryBuilder $qb): IQueryBuilder => $qb->where($qb->expr()->lte('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))));
	}

	/**
	 * @param array<string, mixed> $row
	 * @return array{uid: string, reason: string, detection_id: ?string, created_at: int, expires_at: int}
	 */
	private static function row(array $row): array {
		return [
			'uid' => (string)$row['uid'],
			'reason' => (string)$row['reason'],
			'detection_id' => $row['detection_id'] === null ? null : (string)$row['detection_id'],
			'created_at' => (int)$row['created_at'],
			'expires_at' => (int)$row['expires_at'],
		];
	}
}
