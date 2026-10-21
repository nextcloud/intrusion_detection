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
 * Sessions whose login was not confirmed (ids_step_up_sessions), by a keyed
 * fingerprint of the session id. Never the session id itself.
 */
class StepUpSessionMapper {
	public const TABLE = 'ids_step_up_sessions';

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	public function record(string $sessionKey, string $uid, int $now, int $expiresAt): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('uid', $qb->createNamedParameter($uid))
			->set('expires_at', $qb->createNamedParameter($expiresAt, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('session_key', $qb->createNamedParameter($sessionKey)));
		if ($qb->executeStatement() > 0) {
			return;
		}
		$this->db->insertIgnoreConflict(self::TABLE, [
			'session_key' => $sessionKey,
			'uid' => $uid,
			'created_at' => $now,
			'expires_at' => $expiresAt,
		]);
	}

	/**
	 * @return ?string the account of the unexpired entry, or null
	 */
	public function find(string $sessionKey, int $now): ?string {
		$qb = $this->db->getQueryBuilder();
		$qb->select('uid')
			->from(self::TABLE)
			->where($qb->expr()->eq('session_key', $qb->createNamedParameter($sessionKey)))
			->andWhere($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$uid = $result->fetchOne();
		$result->closeCursor();
		return $uid === false ? null : (string)$uid;
	}

	public function delete(string $sessionKey): void {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('session_key', $qb->createNamedParameter($sessionKey)))
			->executeStatement();
	}

	public function deleteExpired(int $now): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->lte('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement();
	}
}
