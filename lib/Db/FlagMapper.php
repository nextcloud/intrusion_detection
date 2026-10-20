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
 * Flagged sources and passwords (ids_flags). A flag makes successful logins
 * from that source, or with that password, ask for extra confirmation.
 */
class FlagMapper {
	public const TABLE = 'ids_flags';

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * Set a flag, or extend it when it would expire earlier.
	 */
	public function flag(string $flagKey, string $reason, int $expiresAt, ?int $detectionId): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('expires_at', $qb->createNamedParameter($expiresAt, IQueryBuilder::PARAM_INT))
			->set('reason', $qb->createNamedParameter($reason))
			->where($qb->expr()->eq('flag_key', $qb->createNamedParameter($flagKey)))
			->andWhere($qb->expr()->lt('expires_at', $qb->createNamedParameter($expiresAt, IQueryBuilder::PARAM_INT)));
		if ($qb->executeStatement() > 0) {
			return;
		}
		// A flag that already expires later stays as it is.
		$this->db->insertIgnoreConflict(self::TABLE, [
			'flag_key' => $flagKey,
			'reason' => $reason,
			'detection_id' => $detectionId,
			'expires_at' => $expiresAt,
		]);
	}

	/**
	 * The keys among the given ones that are flagged right now.
	 *
	 * @param list<string> $flagKeys
	 * @return array<string, string> reason per flagged key
	 */
	public function active(array $flagKeys, int $now): array {
		if ($flagKeys === []) {
			return [];
		}
		$qb = $this->db->getQueryBuilder();
		$qb->select('flag_key', 'reason')
			->from(self::TABLE)
			->where($qb->expr()->in('flag_key', $qb->createNamedParameter($flagKeys, IQueryBuilder::PARAM_STR_ARRAY)))
			->andWhere($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$flags = [];
		while ($row = $result->fetch()) {
			$flags[(string)$row['flag_key']] = (string)$row['reason'];
		}
		$result->closeCursor();
		return $flags;
	}

	public function unflag(string $flagKey): void {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('flag_key', $qb->createNamedParameter($flagKey)))
			->executeStatement();
	}

	public function deleteExpired(int $now): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->lte('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement();
	}
}
