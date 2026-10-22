<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\StaleCredential\Db;

use OC\Authentication\Token\PublicKeyToken;
use OCP\Authentication\Token\IToken;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

/**
 * Reads core's token table (authtoken) across all accounts, for the daily
 * look at app passwords and remembered browser sessions nobody used for a
 * long time. Core's token provider only lists the tokens of one account,
 * so this is the app's one direct read of that table.
 *
 * Only the id, account, name, type and last activity are ever selected,
 * never the token, its password or its keys. Removing goes through core's
 * token provider.
 */
class StaleTokenMapper {
	public const TABLE = 'authtoken';

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * Whether a token of this type and remember state can go unused for
	 * long: an app password, or a browser session with "Remember me".
	 * Other sessions expire within a day, and remote wipe tokens and
	 * one-time tokens are not credentials a user manages.
	 */
	public static function isLongLived(int $type, int $remember): bool {
		return $type === IToken::PERMANENT_TOKEN || ($type === IToken::TEMPORARY_TOKEN && $remember === IToken::REMEMBER);
	}

	/**
	 * One page of the accounts that have long-lived tokens last used before
	 * $before, by uid, with their counts and the oldest and newest last use.
	 *
	 * @param ?string $afterUid the uid the previous page ended with
	 * @return list<array{uid: string, appPasswords: int, sessions: int, oldest: int, newest: int}>
	 */
	public function accounts(int $before, ?string $afterUid, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$permanent = $qb->createNamedParameter(IToken::PERMANENT_TOKEN, IQueryBuilder::PARAM_INT);
		$qb->select('uid')
			->selectAlias($qb->createFunction('SUM(CASE WHEN ' . $qb->getColumnName('type') . ' = ' . $permanent . ' THEN 1 ELSE 0 END)'), 'app_passwords')
			->selectAlias($qb->func()->count('id'), 'total')
			->selectAlias($qb->func()->min('last_activity'), 'oldest')
			->selectAlias($qb->func()->max('last_activity'), 'newest')
			->from(self::TABLE);
		$this->stale($qb, $before);
		if ($afterUid !== null) {
			$qb->andWhere($qb->expr()->gt('uid', $qb->createNamedParameter($afterUid)));
		}
		$qb->groupBy('uid')
			->orderBy('uid')
			->setMaxResults($limit);
		$result = $qb->executeQuery();
		$accounts = [];
		while ($row = $result->fetch()) {
			$apps = (int)$row['app_passwords'];
			$accounts[] = [
				'uid' => (string)$row['uid'],
				'appPasswords' => $apps,
				'sessions' => (int)$row['total'] - $apps,
				'oldest' => (int)$row['oldest'],
				'newest' => (int)$row['newest'],
			];
		}
		$result->closeCursor();
		return $accounts;
	}

	/**
	 * How many long-lived tokens were last used before $before, and of how many accounts.
	 *
	 * @return array{credentials: int, accounts: int}
	 */
	public function count(int $before): array {
		$qb = $this->db->getQueryBuilder();
		$qb->selectAlias($qb->func()->count('id'), 'credentials')
			->selectAlias($qb->createFunction('COUNT(DISTINCT ' . $qb->getColumnName('uid') . ')'), 'accounts')
			->from(self::TABLE);
		$this->stale($qb, $before);
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		return ['credentials' => (int)($row['credentials'] ?? 0), 'accounts' => (int)($row['accounts'] ?? 0)];
	}

	/**
	 * One page of the long-lived tokens last used before $before, by id.
	 *
	 * @param ?string $uid only this account's
	 * @param int $afterId the id the previous page ended with
	 * @return list<array{id: int, uid: string, name: string, type: int, lastActivity: int}>
	 */
	public function tokens(int $before, ?string $uid, int $afterId, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id', 'uid', 'name', 'type', 'last_activity')
			->from(self::TABLE);
		$this->stale($qb, $before);
		if ($uid !== null) {
			$qb->andWhere($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		}
		$qb->andWhere($qb->expr()->gt('id', $qb->createNamedParameter($afterId, IQueryBuilder::PARAM_INT)))
			->orderBy('id')
			->setMaxResults($limit);
		$result = $qb->executeQuery();
		$tokens = [];
		while ($row = $result->fetch()) {
			$tokens[] = [
				'id' => (int)$row['id'],
				'uid' => (string)$row['uid'],
				'name' => (string)$row['name'],
				'type' => (int)$row['type'],
				'lastActivity' => (int)$row['last_activity'],
			];
		}
		$result->closeCursor();
		return $tokens;
	}

	/**
	 * Long-lived tokens of core's current token version last used before
	 * $before, through the index on last_activity.
	 */
	private function stale(IQueryBuilder $qb, int $before): void {
		$qb->where($qb->expr()->lt('last_activity', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('version', $qb->createNamedParameter(PublicKeyToken::VERSION, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->orX(
				$qb->expr()->eq('type', $qb->createNamedParameter(IToken::PERMANENT_TOKEN, IQueryBuilder::PARAM_INT)),
				$qb->expr()->andX(
					$qb->expr()->eq('type', $qb->createNamedParameter(IToken::TEMPORARY_TOKEN, IQueryBuilder::PARAM_INT)),
					$qb->expr()->eq('remember', $qb->createNamedParameter(IToken::REMEMBER, IQueryBuilder::PARAM_INT)),
				),
			));
	}
}
