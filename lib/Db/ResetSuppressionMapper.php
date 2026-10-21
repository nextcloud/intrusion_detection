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

	public function deleteExpired(int $now): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->lte('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement();
	}
}
