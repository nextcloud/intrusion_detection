<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\LoginHistory\Db;

use OCA\IntrusionDetection\Db\BatchedDelete;
use OCA\IntrusionDetection\Db\KeyMatch;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\LoginHistory\LoginHistoryEntry;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\DB\QueryBuilder\ICompositeExpression;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

/**
 * The login history (ids_login_history): one row per successful login,
 * written with a single insert on the login path. Read by account or by
 * address, always within a time range and with a limit, through the
 * indexes (uid, created_at), (ip, created_at) and (net_key, created_at).
 */
class LoginHistoryMapper {
	public const TABLE = 'ids_login_history';
	/** Lists return at most this many rows: enough for a full incident report */
	public const MAX_LIMIT = 2001;
	private const COLUMNS = ['id', 'uid', 'created_at', 'ip', 'net_key', 'user_agent', 'method', 'known_device', 'confirmed_by', 'step_up', 'session_token_id'];

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * @return int the id of the new row
	 */
	public function insert(string $uid, int $now, ?SourceKey $source, ?string $userAgent, string $method, bool $knownDevice, string $confirmedBy, ?string $stepUp, ?int $sessionTokenId): int {
		$qb = $this->db->getQueryBuilder();
		$qb->insert(self::TABLE)
			->values([
				'uid' => $qb->createNamedParameter($uid),
				'created_at' => $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT),
				'ip' => $qb->createNamedParameter($source?->ip),
				'net_key' => $qb->createNamedParameter($source?->netKey),
				'user_agent' => $qb->createNamedParameter($userAgent),
				'method' => $qb->createNamedParameter($method),
				'known_device' => $qb->createNamedParameter($knownDevice, IQueryBuilder::PARAM_BOOL),
				'confirmed_by' => $qb->createNamedParameter($confirmedBy),
				'step_up' => $qb->createNamedParameter($stepUp),
				'session_token_id' => $qb->createNamedParameter($sessionTokenId, $sessionTokenId === null ? IQueryBuilder::PARAM_NULL : IQueryBuilder::PARAM_INT),
			])
			->executeStatement();
		return $qb->getLastInsertId();
	}

	/**
	 * How the login of a row was confirmed, once that is known.
	 */
	public function setOutcome(int $id, string $uid, string $confirmedBy, ?string $stepUp): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('confirmed_by', $qb->createNamedParameter($confirmedBy))
			->set('step_up', $qb->createNamedParameter($stepUp))
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->executeStatement();
	}

	/**
	 * A login without extra confirmation passed core's second factor.
	 */
	public function setSecondFactor(int $id, string $uid): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('confirmed_by', $qb->createNamedParameter('second_factor'))
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->eq('confirmed_by', $qb->createNamedParameter('none')))
			->andWhere($qb->expr()->isNull('step_up'))
			->executeStatement();
	}

	public function setSessionToken(int $id, string $uid, int $tokenId): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('session_token_id', $qb->createNamedParameter($tokenId, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->executeStatement();
	}

	/**
	 * Whether the account logged in this way since a time, with this token
	 * (if any) and from this network (if any).
	 */
	public function existsSince(string $uid, string $method, ?int $tokenId, ?string $netKey, int $since): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('method', $qb->createNamedParameter($method)))
			->setMaxResults(1);
		if ($tokenId !== null) {
			$qb->andWhere($qb->expr()->eq('session_token_id', $qb->createNamedParameter($tokenId, IQueryBuilder::PARAM_INT)));
		}
		if ($netKey !== null) {
			$qb->andWhere($qb->expr()->eq('net_key', $qb->createNamedParameter($netKey)));
		}
		$result = $qb->executeQuery();
		$found = $result->fetchOne() !== false;
		$result->closeCursor();
		return $found;
	}

	/**
	 * The newest login of the account since a time that the session token
	 * is linked to.
	 */
	public function idForSessionToken(string $uid, int $tokenId, int $since): ?int {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('session_token_id', $qb->createNamedParameter($tokenId, IQueryBuilder::PARAM_INT)))
			->orderBy('id', 'DESC')
			->setMaxResults(1);
		$result = $qb->executeQuery();
		$id = $result->fetchOne();
		$result->closeCursor();
		return $id === false ? null : (int)$id;
	}

	/**
	 * Whether the account logged in from this network (as in
	 * {@see SourceKey::$netKey}) since a time with a login that went
	 * through: it needed nothing, or it was confirmed. Logins let in
	 * without a confirmation never count.
	 */
	public function wentThroughFrom(string $uid, string $netKey, int $since): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id')
			->from(self::TABLE)
			->where($qb->expr()->eq('net_key', $qb->createNamedParameter($netKey)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->orX(
				$qb->expr()->isNull('step_up'),
				$qb->expr()->eq('step_up', $qb->createNamedParameter('confirmed')),
			))
			->setMaxResults(1);
		$result = $qb->executeQuery();
		$found = $result->fetchOne() !== false;
		$result->closeCursor();
		return $found;
	}

	/**
	 * @return list<LoginHistoryEntry> the account's logins in [since, until), newest first unless `$oldestFirst`
	 */
	public function forUser(string $uid, int $since, ?int $until = null, int $limit = 100, bool $oldestFirst = false): array {
		$qb = $this->db->getQueryBuilder();
		$qb->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		return $this->range($qb, $since, $until, $limit, $oldestFirst);
	}

	/**
	 * The logins from one address, or from a network when given its key
	 * (as in {@see SourceKey::$netKey}), in [since, until), newest first
	 * unless `$oldestFirst`.
	 *
	 * @return list<LoginHistoryEntry>
	 */
	public function forAddress(string $address, int $since, ?int $until = null, int $limit = 100, bool $oldestFirst = false): array {
		$qb = $this->db->getQueryBuilder();
		$source = SourceKey::tryFromIp($address);
		if ($source !== null) {
			$qb->where($qb->expr()->eq('ip', $qb->createNamedParameter($source->ip)));
		} else {
			$qb->where($qb->expr()->eq('net_key', $qb->createNamedParameter($address)));
		}
		return $this->range($qb, $since, $until, $limit, $oldestFirst);
	}

	/**
	 * The newest login of an account that started a session (or app
	 * password) token.
	 */
	public function forSession(string $uid, int $sessionTokenId): ?LoginHistoryEntry {
		$qb = $this->db->getQueryBuilder();
		$qb->select(...self::COLUMNS)
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->eq('session_token_id', $qb->createNamedParameter($sessionTokenId, IQueryBuilder::PARAM_INT)))
			->orderBy('created_at', 'DESC')
			->addOrderBy('id', 'DESC')
			->setMaxResults(1);
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		return is_array($row) ? LoginHistoryEntry::fromRow($row) : null;
	}

	/** Logins with a step-up looked at around a time */
	private const AROUND_ROWS = 20;

	/**
	 * The row of a login with this step-up outcome (`pending`, `refused`),
	 * recorded around when it started. Only the login with a step-up
	 * nearest to that time counts, so that a refused login next to a
	 * pending one of the same account is not taken for the other. The session's row and the history
	 * share no key: the session is kept only as a keyed fingerprint of its
	 * id, the history by its token.
	 */
	public function stepUpAround(string $uid, int $started, string $stepUp): ?LoginHistoryEntry {
		$qb = $this->db->getQueryBuilder();
		$qb->select(...self::COLUMNS)
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($started - 5, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lte('created_at', $qb->createNamedParameter($started + 60, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->isNotNull('step_up'))
			->orderBy('created_at', 'ASC')
			->addOrderBy('id', 'ASC')
			->setMaxResults(self::AROUND_ROWS);
		$result = $qb->executeQuery();
		$nearest = null;
		while ($row = $result->fetch()) {
			$entry = LoginHistoryEntry::fromRow($row);
			if ($nearest === null || abs($entry->createdAt - $started) < abs($nearest->createdAt - $started)) {
				$nearest = $entry;
			}
		}
		$result->closeCursor();
		return $nearest !== null && $nearest->stepUp === $stepUp ? $nearest : null;
	}

	/**
	 * The different accounts with logins from an address (`ip`) or networks
	 * (`net_key`) since a time that were not refused or left unconfirmed, at
	 * most `$limit`. Distinct, so that the many logins of one client never
	 * hide another account.
	 *
	 * @param 'ip'|'net_key' $column
	 * @return list<string>
	 */
	public function acceptedUidsFrom(string $column, KeyMatch $keys, int $since, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->selectDistinct('uid')
			->from(self::TABLE)
			->where($keys->condition($qb, $column))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($this->accepted($qb))
			->setMaxResults($limit);
		$result = $qb->executeQuery();
		$uids = array_map('strval', $result->fetchFirstColumn());
		$result->closeCursor();
		return $uids;
	}

	/**
	 * Whether the account confirmed a login (a second factor, an email code,
	 * admin approval or a remembered device) from an address (`ip`) or
	 * networks (`net_key`) since a time.
	 *
	 * @param 'ip'|'net_key' $column
	 */
	public function hasConfirmedLogin(string $uid, string $column, KeyMatch $keys, int $since): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($keys->condition($qb, $column))
			->andWhere($this->accepted($qb))
			->andWhere($qb->expr()->orX(
				$qb->expr()->eq('known_device', $qb->createNamedParameter(true, IQueryBuilder::PARAM_BOOL)),
				$qb->expr()->neq('confirmed_by', $qb->createNamedParameter(LoginHistory::CONFIRMED_BY_NONE)),
			))
			->setMaxResults(1);
		$result = $qb->executeQuery();
		$found = $result->fetchOne() !== false;
		$result->closeCursor();
		return $found;
	}

	public function deleteOlderThan(int $before): int {
		return BatchedDelete::run($this->db, self::TABLE, 'id', 'created_at', static fn (IQueryBuilder $qb): IQueryBuilder => $qb->where($qb->expr()->lt('created_at', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT))));
	}

	/**
	 * Logins that were not refused or left unconfirmed.
	 */
	private function accepted(IQueryBuilder $qb): ICompositeExpression {
		return $qb->expr()->orX(
			$qb->expr()->isNull('step_up'),
			$qb->expr()->in('step_up', $qb->createNamedParameter([LoginHistory::STEP_UP_CONFIRMED, LoginHistory::STEP_UP_ALLOWED], IQueryBuilder::PARAM_STR_ARRAY)),
		);
	}

	/**
	 * @return list<LoginHistoryEntry>
	 */
	private function range(IQueryBuilder $qb, int $since, ?int $until, int $limit, bool $oldestFirst): array {
		$order = $oldestFirst ? 'ASC' : 'DESC';
		$qb->select(...self::COLUMNS)
			->from(self::TABLE)
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->orderBy('created_at', $order)
			->addOrderBy('id', $order)
			->setMaxResults(max(1, min(self::MAX_LIMIT, $limit)));
		if ($until !== null) {
			$qb->andWhere($qb->expr()->lt('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)));
		}
		$result = $qb->executeQuery();
		$entries = [];
		while ($row = $result->fetch()) {
			$entries[] = LoginHistoryEntry::fromRow($row);
		}
		$result->closeCursor();
		return $entries;
	}
}
