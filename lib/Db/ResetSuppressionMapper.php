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
 * Accounts whose password reset emails are held back
 * (ids_reset_suppressions), one row per account, keyed by uid.
 */
class ResetSuppressionMapper {
	public const TABLE = 'ids_reset_suppressions';

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * Suppress until a time, or extend a suppression that would end earlier.
	 * One that already lasts longer stays as it is.
	 */
	public function suppress(string $uid, ?int $detectionId, int $now, int $expiresAt): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('expires_at', $qb->createNamedParameter($expiresAt, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->lt('expires_at', $qb->createNamedParameter($expiresAt, IQueryBuilder::PARAM_INT)));
		if ($detectionId !== null) {
			$qb->set('detection_id', $qb->createNamedParameter($detectionId, IQueryBuilder::PARAM_INT));
		}
		if ($qb->executeStatement() > 0) {
			return;
		}
		$this->db->insertIgnoreConflict(self::TABLE, [
			'uid' => $uid,
			'detection_id' => $detectionId,
			'created_at' => $now,
			'expires_at' => $expiresAt,
		]);
	}

	/**
	 * When the account's suppression started and when it ends, or null.
	 *
	 * @return ?array{createdAt: int, expiresAt: int}
	 */
	public function find(string $uid): ?array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('created_at', 'expires_at')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		return is_array($row) ? ['createdAt' => (int)$row['created_at'], 'expiresAt' => (int)$row['expires_at']] : null;
	}

	/**
	 * When the account's suppression ends, 0 if it has none.
	 */
	public function expiresAt(string $uid): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select('expires_at')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		$result = $qb->executeQuery();
		$value = $result->fetchOne();
		$result->closeCursor();
		return $value === false ? 0 : (int)$value;
	}

	public function delete(string $uid): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		return $qb->executeStatement() > 0;
	}

	/**
	 * Delete suppressions that ended and started before a time, in batches:
	 * a row is kept for its whole period, so that a new suppression cannot
	 * start in it.
	 */
	public function deleteExpired(int $now, int $startedBefore = PHP_INT_MAX): int {
		return BatchedDelete::run(
			$this->db,
			self::TABLE,
			'uid',
			'expires_at',
			static fn (IQueryBuilder $qb): IQueryBuilder => $qb
				->where($qb->expr()->lte('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)))
				->andWhere($qb->expr()->lt('created_at', $qb->createNamedParameter($startedBefore, IQueryBuilder::PARAM_INT))),
			IQueryBuilder::PARAM_STR_ARRAY,
		);
	}
}
