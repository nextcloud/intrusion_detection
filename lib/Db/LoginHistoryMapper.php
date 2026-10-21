<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCA\IntrusionDetection\LoginHistory\LoginHistoryEntry;
use OCA\IntrusionDetection\Net\SourceKey;
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
	 * or, without one, from this address.
	 */
	public function existsSince(string $uid, string $method, ?int $tokenId, ?string $ip, int $since): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('method', $qb->createNamedParameter($method)))
			->setMaxResults(1);
		if ($tokenId !== null) {
			$qb->andWhere($qb->expr()->eq('session_token_id', $qb->createNamedParameter($tokenId, IQueryBuilder::PARAM_INT)));
		} elseif ($ip !== null) {
			$qb->andWhere($qb->expr()->eq('ip', $qb->createNamedParameter($ip)));
		}
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

	public function deleteOlderThan(int $before): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->lt('created_at', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement();
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
