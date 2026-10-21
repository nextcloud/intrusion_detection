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
 * One-time lock links (ids_lock_links). A link is stored with a keyed
 * fingerprint of its token, never the token itself.
 *
 * @psalm-type LockLinkRow = array{id: int, uid: string, token_hash: string, sent_to_hint: string, detection_id: ?int, change_id: ?int, created_at: int, expires_at: int, used_at: ?int, used_ip: ?string}
 */
class LockLinkMapper {
	public const TABLE = 'ids_lock_links';

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	public function insert(string $uid, string $tokenHash, string $sentToHint, ?int $detectionId, ?int $changeId, int $now, int $expiresAt): int {
		$qb = $this->db->getQueryBuilder();
		$qb->insert(self::TABLE)->values([
			'uid' => $qb->createNamedParameter($uid),
			'token_hash' => $qb->createNamedParameter($tokenHash),
			'sent_to_hint' => $qb->createNamedParameter($sentToHint),
			'detection_id' => $qb->createNamedParameter($detectionId, $detectionId === null ? IQueryBuilder::PARAM_NULL : IQueryBuilder::PARAM_INT),
			'change_id' => $qb->createNamedParameter($changeId, $changeId === null ? IQueryBuilder::PARAM_NULL : IQueryBuilder::PARAM_INT),
			'created_at' => $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT),
			'expires_at' => $qb->createNamedParameter($expiresAt, IQueryBuilder::PARAM_INT),
		])->executeStatement();
		return $qb->getLastInsertId();
	}

	/**
	 * @return ?LockLinkRow
	 */
	public function find(int $id): ?array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		return is_array($row) ? self::row($row) : null;
	}

	public function existsForDetection(int $detectionId): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id')
			->from(self::TABLE)
			->where($qb->expr()->eq('detection_id', $qb->createNamedParameter($detectionId, IQueryBuilder::PARAM_INT)))
			->setMaxResults(1);
		$result = $qb->executeQuery();
		$found = $result->fetchOne() !== false;
		$result->closeCursor();
		return $found;
	}

	/**
	 * Mark a link used, once: only the first of concurrent requests wins.
	 *
	 * @return bool whether this call used it
	 */
	public function use(int $id, int $now, ?string $ip): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('used_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))
			->set('used_ip', $qb->createNamedParameter($ip, $ip === null ? IQueryBuilder::PARAM_NULL : IQueryBuilder::PARAM_STR))
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->isNull('used_at'))
			->andWhere($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement() === 1;
	}

	/**
	 * The newest used link of the account, if any: the account was locked with it.
	 *
	 * @return ?LockLinkRow
	 */
	public function lastUsed(string $uid): ?array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->isNotNull('used_at'))
			->orderBy('used_at', 'DESC')
			->setMaxResults(1);
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		return is_array($row) ? self::row($row) : null;
	}

	public function deleteExpired(int $now): int {
		return BatchedDelete::run($this->db, self::TABLE, 'id', 'expires_at', static fn (IQueryBuilder $qb): IQueryBuilder => $qb->where($qb->expr()->lte('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))));
	}

	/**
	 * @param array<string, mixed> $row
	 * @return LockLinkRow
	 */
	private static function row(array $row): array {
		return [
			'id' => (int)$row['id'],
			'uid' => (string)$row['uid'],
			'token_hash' => (string)$row['token_hash'],
			'sent_to_hint' => (string)$row['sent_to_hint'],
			'detection_id' => $row['detection_id'] === null ? null : (int)$row['detection_id'],
			'change_id' => $row['change_id'] === null ? null : (int)$row['change_id'],
			'created_at' => (int)$row['created_at'],
			'expires_at' => (int)$row['expires_at'],
			'used_at' => $row['used_at'] === null ? null : (int)$row['used_at'],
			'used_ip' => $row['used_ip'] === null ? null : (string)$row['used_ip'],
		];
	}
}
