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
 * Where each app password came from (ids_token_origin): its token id, the
 * account, the address and the session that created it. Only identifiers
 * are stored, never a token. Kept for 30 days.
 */
class TokenOriginMapper {
	public const TABLE = 'ids_token_origin';

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * Record one app password; a token id is recorded once.
	 */
	public function record(int $tokenId, string $uid, ?string $ip, ?int $sessionTokenId, int $createdAt): void {
		$this->db->insertIgnoreConflict(self::TABLE, [
			'token_id' => $tokenId,
			'uid' => $uid,
			'ip' => $ip,
			'session_token_id' => $sessionTokenId,
			'created_at' => $createdAt,
		]);
	}

	/**
	 * Where several app passwords and sessions came from, in one query.
	 *
	 * @param list<int> $tokenIds
	 * @return array<int, array{token_id: int, uid: string, ip: ?string, session_token_id: ?int, created_at: int}> by token id; tokens without a row are missing
	 */
	public function findMany(array $tokenIds): array {
		$rows = [];
		foreach (array_chunk(array_values(array_unique($tokenIds)), 1000) as $chunk) {
			$qb = $this->db->getQueryBuilder();
			$qb->select('token_id', 'uid', 'ip', 'session_token_id', 'created_at')
				->from(self::TABLE)
				->where($qb->expr()->in('token_id', $qb->createNamedParameter($chunk, IQueryBuilder::PARAM_INT_ARRAY)));
			$result = $qb->executeQuery();
			while ($row = $result->fetch()) {
				$rows[(int)$row['token_id']] = self::row($row);
			}
			$result->closeCursor();
		}
		return $rows;
	}

	/**
	 * @return ?array{token_id: int, uid: string, ip: ?string, session_token_id: ?int, created_at: int}
	 */
	public function find(int $tokenId): ?array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('token_id', 'uid', 'ip', 'session_token_id', 'created_at')
			->from(self::TABLE)
			->where($qb->expr()->eq('token_id', $qb->createNamedParameter($tokenId, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		return $row === false ? null : self::row($row);
	}

	/**
	 * The app passwords of an account created from one session or token.
	 *
	 * @return list<int> token ids
	 */
	public function createdBy(string $uid, int $sessionTokenId, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('token_id')
			->from(self::TABLE)
			->where($qb->expr()->eq('session_token_id', $qb->createNamedParameter($sessionTokenId, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->orderBy('token_id', 'ASC')
			->setMaxResults($limit);
		return $this->ids($qb);
	}

	/**
	 * The app passwords of an account created from one address since a time.
	 *
	 * @return list<int> token ids
	 */
	public function createdFrom(string $uid, string $ip, int $since, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('token_id')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('ip', $qb->createNamedParameter($ip)))
			->orderBy('token_id', 'ASC')
			->setMaxResults($limit);
		return $this->ids($qb);
	}

	/**
	 * The app passwords of an account, or created from an address, in a
	 * period. Oldest first.
	 *
	 * @return list<array{token_id: int, uid: string, ip: ?string, session_token_id: ?int, created_at: int}>
	 */
	public function findInPeriod(?string $uid, ?string $ip, int $since, int $until, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('token_id', 'uid', 'ip', 'session_token_id', 'created_at')
			->from(self::TABLE)
			->where($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lte('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->orderBy('created_at', 'ASC')
			->addOrderBy('token_id', 'ASC')
			->setMaxResults($limit);
		if ($uid !== null) {
			$qb->andWhere($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		} elseif ($ip !== null) {
			$qb->andWhere($qb->expr()->eq('ip', $qb->createNamedParameter($ip)));
		} else {
			return [];
		}
		$result = $qb->executeQuery();
		$rows = [];
		while ($row = $result->fetch()) {
			$rows[] = self::row($row);
		}
		$result->closeCursor();
		return $rows;
	}

	public function deleteOlderThan(int $before): int {
		return BatchedDelete::run($this->db, self::TABLE, 'token_id', static fn (IQueryBuilder $qb): IQueryBuilder => $qb->where($qb->expr()->lt('created_at', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT))));
	}

	/**
	 * @return list<int>
	 */
	private function ids(IQueryBuilder $qb): array {
		$result = $qb->executeQuery();
		$ids = array_map('intval', $result->fetchFirstColumn());
		$result->closeCursor();
		return $ids;
	}

	/**
	 * @param array<string, mixed> $row
	 * @return array{token_id: int, uid: string, ip: ?string, session_token_id: ?int, created_at: int}
	 */
	private static function row(array $row): array {
		return [
			'token_id' => (int)$row['token_id'],
			'uid' => (string)$row['uid'],
			'ip' => $row['ip'] === null ? null : (string)$row['ip'],
			'session_token_id' => $row['session_token_id'] === null ? null : (int)$row['session_token_id'],
			'created_at' => (int)$row['created_at'],
		];
	}
}
