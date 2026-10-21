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
 * Sessions that must confirm sensitive actions (ids_risky_sessions), by the
 * database id of their token. Never the token itself.
 */
class RiskySessionMapper {
	public const TABLE = 'ids_risky_sessions';

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	public function record(int $tokenId, string $uid, string $checkId, ?int $detectionId, int $now, int $expiresAt): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('check_id', $qb->createNamedParameter($checkId))
			->set('detection_id', $qb->createNamedParameter($detectionId, $detectionId === null ? IQueryBuilder::PARAM_NULL : IQueryBuilder::PARAM_INT))
			->set('expires_at', $qb->createNamedParameter($expiresAt, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('token_id', $qb->createNamedParameter($tokenId, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		if ($qb->executeStatement() > 0) {
			return;
		}
		$this->db->insertIgnoreConflict(self::TABLE, [
			'token_id' => $tokenId,
			'uid' => $uid,
			'check_id' => $checkId,
			'detection_id' => $detectionId,
			'created_at' => $now,
			'expires_at' => $expiresAt,
		]);
	}

	/**
	 * @return ?array{check: string, detection: ?int} the unexpired mark of the session's token for the account, or null
	 */
	public function find(int $tokenId, string $uid, int $now): ?array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('check_id', 'detection_id')
			->from(self::TABLE)
			->where($qb->expr()->eq('token_id', $qb->createNamedParameter($tokenId, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		if (!is_array($row)) {
			return null;
		}
		return ['check' => (string)$row['check_id'], 'detection' => $row['detection_id'] === null ? null : (int)$row['detection_id']];
	}

	public function deleteExpired(int $now): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->lte('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement();
	}
}
