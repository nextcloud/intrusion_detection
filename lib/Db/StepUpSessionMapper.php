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

	/**
	 * @param ?int $deadline until when a pending login may wait; null for a refused one
	 * @param list<string> $policies
	 */
	public function record(string $sessionKey, string $uid, int $now, int $expiresAt, ?int $deadline = null, ?string $ip = null, array $policies = []): void {
		$policyList = $policies === [] ? null : substr(implode(',', $policies), 0, 255);
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('uid', $qb->createNamedParameter($uid))
			->set('expires_at', $qb->createNamedParameter($expiresAt, IQueryBuilder::PARAM_INT))
			->set('deadline', $qb->createNamedParameter($deadline, IQueryBuilder::PARAM_INT))
			->set('ip', $qb->createNamedParameter($ip))
			->set('policies', $qb->createNamedParameter($policyList))
			->set('attempts', $qb->createNamedParameter(0, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('session_key', $qb->createNamedParameter($sessionKey)));
		if ($qb->executeStatement() > 0) {
			return;
		}
		$this->db->insertIgnoreConflict(self::TABLE, [
			'session_key' => $sessionKey,
			'uid' => $uid,
			'created_at' => $now,
			'expires_at' => $expiresAt,
			'deadline' => $deadline,
			'ip' => $ip,
			'policies' => $policyList,
			'attempts' => 0,
		]);
	}

	/**
	 * Count one try of the pending login's email code, unless it has used
	 * all of them. One conditional update, so that parallel requests never
	 * get more tries than `$max` between them.
	 *
	 * @return ?int the tries used, this one included; null when none is left or the session is not remembered (any more)
	 */
	public function takeAttempt(string $sessionKey, int $max): ?int {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('attempts', $qb->createFunction($qb->getColumnName('attempts') . ' + 1'))
			->where($qb->expr()->eq('session_key', $qb->createNamedParameter($sessionKey)))
			->andWhere($qb->expr()->lt('attempts', $qb->createNamedParameter($max, IQueryBuilder::PARAM_INT)));
		$taken = $qb->executeStatement() > 0;

		$qb = $this->db->getQueryBuilder();
		$qb->select('attempts')
			->from(self::TABLE)
			->where($qb->expr()->eq('session_key', $qb->createNamedParameter($sessionKey)));
		$result = $qb->executeQuery();
		$attempts = $result->fetchOne();
		$result->closeCursor();
		return $taken && $attempts !== false ? (int)$attempts : null;
	}

	/**
	 * A pending login may wait longer (an administrator's approval).
	 */
	public function extendDeadline(string $sessionKey, int $deadline): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('deadline', $qb->createNamedParameter($deadline, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('session_key', $qb->createNamedParameter($sessionKey)))
			->andWhere($qb->expr()->isNotNull('deadline'))
			->andWhere($qb->expr()->lt('deadline', $qb->createNamedParameter($deadline, IQueryBuilder::PARAM_INT)))
			->executeStatement();
	}

	/**
	 * Pending logins whose deadline has passed, oldest first.
	 *
	 * @return list<array{session_key: string, uid: string, created_at: int, deadline: int, ip: ?string, policies: list<string>}>
	 */
	public function findAbandoned(int $now, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('session_key', 'uid', 'created_at', 'deadline', 'ip', 'policies')
			->from(self::TABLE)
			->where($qb->expr()->lte('deadline', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)))
			->orderBy('deadline', 'ASC')
			->setMaxResults($limit);
		$result = $qb->executeQuery();
		$rows = [];
		while ($row = $result->fetch()) {
			$rows[] = [
				'session_key' => (string)$row['session_key'],
				'uid' => (string)$row['uid'],
				'created_at' => (int)$row['created_at'],
				'deadline' => (int)$row['deadline'],
				'ip' => $row['ip'] === null ? null : (string)$row['ip'],
				'policies' => $row['policies'] === null || $row['policies'] === '' ? [] : explode(',', (string)$row['policies']),
			];
		}
		$result->closeCursor();
		return $rows;
	}

	/**
	 * Sessions without a deadline that may still come back, by key after
	 * `$after`: refused logins, ended ones, and pending ones remembered
	 * before the deadline was kept.
	 *
	 * @return list<array{session_key: string, uid: string, created_at: int}>
	 */
	public function findWithoutDeadline(int $now, string $after, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('session_key', 'uid', 'created_at')
			->from(self::TABLE)
			->where($qb->expr()->isNull('deadline'))
			->andWhere($qb->expr()->gt('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->gt('session_key', $qb->createNamedParameter($after)))
			->orderBy('session_key', 'ASC')
			->setMaxResults($limit);
		$result = $qb->executeQuery();
		$rows = [];
		while ($row = $result->fetch()) {
			$rows[] = ['session_key' => (string)$row['session_key'], 'uid' => (string)$row['uid'], 'created_at' => (int)$row['created_at']];
		}
		$result->closeCursor();
		return $rows;
	}

	/**
	 * Give a session without a deadline one.
	 */
	public function setDeadline(string $sessionKey, int $deadline): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('deadline', $qb->createNamedParameter($deadline, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('session_key', $qb->createNamedParameter($sessionKey)))
			->andWhere($qb->expr()->isNull('deadline'))
			->executeStatement();
	}

	/**
	 * The pending login was ended; the row stays, so that the session cannot come back.
	 *
	 * @return bool whether this call ended it (and not another one at the same time)
	 */
	public function endWaiting(string $sessionKey): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('deadline', $qb->createNamedParameter(null, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('session_key', $qb->createNamedParameter($sessionKey)))
			->andWhere($qb->expr()->isNotNull('deadline'));
		return $qb->executeStatement() > 0;
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
		return BatchedDelete::run($this->db, self::TABLE, 'session_key', 'expires_at', static fn (IQueryBuilder $qb): IQueryBuilder => $qb->where($qb->expr()->lte('expires_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))), IQueryBuilder::PARAM_STR_ARRAY);
	}
}
