<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Takeover\Db;

use OCA\IntrusionDetection\Db\BatchedDelete;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;
use OCP\Snowflake\ISnowflakeGenerator;

/**
 * The security change log of accounts (ids_security_changes).
 *
 * @psalm-type SecurityChangeRow = array{id: string, uid: string, type: string, via: string, actor_uid: ?string, old_value_hint: ?string, new_value_hint: ?string, ref_id: ?int, detail: ?string, session_token_id: ?int, ip: ?string, created_at: int}
 */
class SecurityChangeMapper {
	public const TABLE = 'ids_security_changes';
	private const COLUMNS = ['id', 'uid', 'type', 'via', 'actor_uid', 'old_value_hint', 'new_value_hint', 'ref_id', 'detail', 'session_token_id', 'ip', 'created_at'];

	public function __construct(
		private readonly IDBConnection $db,
		private readonly ISnowflakeGenerator $snowflakes,
	) {
	}

	/**
	 * @param array{uid: string, type: string, via: string, actor_uid: ?string, old_value_hint: ?string, new_value_hint: ?string, notify_to: ?string, ref_id: ?int, detail: ?string, session_token_id: ?int, ip: ?string, created_at: int} $row
	 * @return string the id of the new row
	 */
	public function insert(array $row): string {
		$id = $this->snowflakes->nextId();
		$qb = $this->db->getQueryBuilder();
		$values = ['id' => $qb->createNamedParameter($id)];
		foreach ($row as $column => $value) {
			$type = is_int($value) ? IQueryBuilder::PARAM_INT : ($value === null ? IQueryBuilder::PARAM_NULL : IQueryBuilder::PARAM_STR);
			$values[$column] = $qb->createNamedParameter($value, $type);
		}
		$qb->insert(self::TABLE)->values($values)->executeStatement();
		return $id;
	}

	/**
	 * The account's changes since a time, oldest first.
	 *
	 * @return list<SecurityChangeRow>
	 */
	public function findSince(string $uid, int $since, int $limit, ?int $until = null): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select(...self::COLUMNS)
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->orderBy('created_at', 'ASC')
			->addOrderBy('id', 'ASC')
			->setMaxResults($limit);
		if ($until !== null) {
			$qb->andWhere($qb->expr()->lte('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)));
		}
		return $this->fetch($qb);
	}

	/**
	 * Changes in a period, of an account or made from an address, oldest first.
	 *
	 * @return list<SecurityChangeRow>
	 */
	public function findInPeriod(?string $uid, ?string $ip, int $since, int $until, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select(...self::COLUMNS)
			->from(self::TABLE)
			->where($uid !== null
				? $qb->expr()->eq('uid', $qb->createNamedParameter($uid))
				: $qb->expr()->eq('ip', $qb->createNamedParameter((string)$ip)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lte('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->orderBy('created_at', 'ASC')
			->addOrderBy('id', 'ASC')
			->setMaxResults($limit);
		return $this->fetch($qb);
	}

	/**
	 * The account's newest changes, newest first.
	 *
	 * @return list<SecurityChangeRow>
	 */
	public function findRecent(string $uid, int $since, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select(...self::COLUMNS)
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->orderBy('created_at', 'DESC')
			->addOrderBy('id', 'DESC')
			->setMaxResults($limit);
		return $this->fetch($qb);
	}

	/**
	 * @return ?SecurityChangeRow
	 */
	public function find(string $id): ?array {
		$qb = $this->db->getQueryBuilder();
		$qb->select(...self::COLUMNS)
			->from(self::TABLE)
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id)));
		return $this->fetch($qb)[0] ?? null;
	}

	/**
	 * The encrypted previous email address of one change, while it is kept.
	 */
	public function notifyTo(string $id): ?string {
		$qb = $this->db->getQueryBuilder();
		$qb->select('notify_to')
			->from(self::TABLE)
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id)));
		$result = $qb->executeQuery();
		$value = $result->fetchOne();
		$result->closeCursor();
		return is_string($value) && $value !== '' ? $value : null;
	}

	/**
	 * Change the kind of the account's change about a token, e.g. an app
	 * password that turned out to be a connected device.
	 *
	 * @return bool whether such a change existed
	 */
	public function retype(string $uid, int $refId, string $from, string $to, string $via, int $since): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('type', $qb->createNamedParameter($to))
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->eq('ref_id', $qb->createNamedParameter($refId, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('type', $qb->createNamedParameter($from)))
			->andWhere($qb->expr()->eq('via', $qb->createNamedParameter($via)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement() > 0;
	}

	/**
	 * Remove the encrypted previous addresses of the changes made between
	 * `$since` and `$before`. Earlier changes were handled by earlier runs,
	 * so the whole history is not read again. The ids are selected through
	 * the created_at index a batch at a time and updated by primary key: as
	 * one statement, MySQL scanned and locked the whole table.
	 */
	public function forgetAddressesBefore(int $before, int $since = 0): int {
		$forgotten = 0;
		$batches = BatchedDelete::batches(
			$this->db,
			self::TABLE,
			'id',
			'created_at',
			static fn (IQueryBuilder $qb): IQueryBuilder => $qb
				->where($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
				->andWhere($qb->expr()->lt('created_at', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT)))
				->andWhere($qb->expr()->isNotNull('notify_to')),
		);
		foreach ($batches as $ids) {
			$qb = $this->db->getQueryBuilder();
			$qb->update(self::TABLE)
				->set('notify_to', $qb->createNamedParameter(null, IQueryBuilder::PARAM_NULL))
				->where($qb->expr()->in('id', $qb->createNamedParameter($ids, IQueryBuilder::PARAM_STR_ARRAY)));
			$forgotten += $qb->executeStatement();
		}
		return $forgotten;
	}

	public function deleteOlderThan(int $before): int {
		return BatchedDelete::run($this->db, self::TABLE, 'id', 'created_at', static fn (IQueryBuilder $qb): IQueryBuilder => $qb->where($qb->expr()->lt('created_at', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT))));
	}

	/**
	 * @return list<SecurityChangeRow>
	 */
	private function fetch(IQueryBuilder $qb): array {
		$result = $qb->executeQuery();
		$rows = [];
		while ($row = $result->fetch()) {
			$rows[] = [
				'id' => (string)$row['id'],
				'uid' => (string)$row['uid'],
				'type' => (string)$row['type'],
				'via' => (string)$row['via'],
				'actor_uid' => $row['actor_uid'] === null ? null : (string)$row['actor_uid'],
				'old_value_hint' => $row['old_value_hint'] === null ? null : (string)$row['old_value_hint'],
				'new_value_hint' => $row['new_value_hint'] === null ? null : (string)$row['new_value_hint'],
				'ref_id' => $row['ref_id'] === null ? null : (int)$row['ref_id'],
				'detail' => $row['detail'] === null ? null : (string)$row['detail'],
				'session_token_id' => $row['session_token_id'] === null ? null : (int)$row['session_token_id'],
				'ip' => $row['ip'] === null ? null : (string)$row['ip'],
				'created_at' => (int)$row['created_at'],
			];
		}
		$result->closeCursor();
		return $rows;
	}
}
