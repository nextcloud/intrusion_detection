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
	 * Set a flag, or extend it to `$expiresAt`. With `$now`, a flag is only
	 * extended once less than half of the new duration remains, so that the
	 * failures of an attack do not rewrite it every time: a flag that lasts
	 * long enough costs one read, an update or an insert only when needed.
	 *
	 * @return bool whether the flag was written
	 */
	public function flag(string $flagKey, string $reason, int $expiresAt, ?int $detectionId, ?int $now = null): bool {
		$extendBelow = $now === null ? $expiresAt : $now + intdiv(max(0, $expiresAt - $now), 2);
		$select = $this->db->getQueryBuilder();
		$select->select('expires_at')
			->from(self::TABLE)
			->where($select->expr()->eq('flag_key', $select->createNamedParameter($flagKey)));
		$result = $select->executeQuery();
		$current = $result->fetchOne();
		$result->closeCursor();
		if ($current !== false) {
			if ((int)$current >= $extendBelow) {
				return false;
			}
			$qb = $this->db->getQueryBuilder();
			$qb->update(self::TABLE)
				->set('expires_at', $qb->createNamedParameter($expiresAt, IQueryBuilder::PARAM_INT))
				->set('reason', $qb->createNamedParameter($reason))
				->where($qb->expr()->eq('flag_key', $qb->createNamedParameter($flagKey)))
				// A parallel request may have extended it meanwhile.
				->andWhere($qb->expr()->lt('expires_at', $qb->createNamedParameter($extendBelow, IQueryBuilder::PARAM_INT)));
			return $qb->executeStatement() > 0;
		}
		return $this->db->insertIgnoreConflict(self::TABLE, [
			'flag_key' => $flagKey,
			'reason' => $reason,
			'detection_id' => $detectionId,
			'expires_at' => $expiresAt,
		]) > 0;
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
		return BatchedDelete::run($this->db, self::TABLE, 'flag_key', static fn (IQueryBuilder $qb): IQueryBuilder => $qb->where($qb->expr()->lte('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))), IQueryBuilder::PARAM_STR_ARRAY);
	}
}
