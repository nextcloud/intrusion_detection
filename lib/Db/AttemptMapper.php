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
 * Failed attempts (ids_attempts), the baseline store for every counter.
 *
 * Detection works from this table alone, so it agrees across all web servers
 * and needs no distributed cache. Rows are deleted after one hour.
 */
class AttemptMapper {
	public const TABLE = 'ids_attempts';

	/** Columns an aggregate may group on, each the first column of an index */
	private const KEY_COLUMNS = ['ip_key', 'net_key', 'pw_fp', 'uid', 'share_id', 'name_hmac'];

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	public function insert(
		AttemptKind $kind,
		string $ipKey,
		string $netKey,
		?string $nameHmac,
		?string $uid,
		?int $shareId,
		?string $pwFp,
		int $createdAt,
		int $weight = 1,
	): void {
		$qb = $this->db->getQueryBuilder();
		$qb->insert(self::TABLE)
			->values([
				'kind' => $qb->createNamedParameter($kind->value, IQueryBuilder::PARAM_INT),
				'ip_key' => $qb->createNamedParameter($ipKey),
				'net_key' => $qb->createNamedParameter($netKey),
				'name_hmac' => $qb->createNamedParameter($nameHmac),
				'uid' => $qb->createNamedParameter($uid),
				'share_id' => $qb->createNamedParameter($shareId, $shareId === null ? IQueryBuilder::PARAM_NULL : IQueryBuilder::PARAM_INT),
				'pw_fp' => $qb->createNamedParameter($pwFp),
				'created_at' => $qb->createNamedParameter($createdAt, IQueryBuilder::PARAM_INT),
				'weight' => $qb->createNamedParameter($weight, IQueryBuilder::PARAM_INT),
			])
			->executeStatement();
	}

	/**
	 * Counts over the attempts where `$column` equals one of `$values`, of
	 * the given kinds, since a time.
	 *
	 * @param 'ip_key'|'net_key'|'pw_fp'|'uid'|'share_id'|'name_hmac' $column
	 * @param list<string|int> $values
	 * @param list<AttemptKind> $kinds
	 */
	public function stats(string $column, array $values, array $kinds, int $since): AttemptStats {
		if (!in_array($column, self::KEY_COLUMNS, true)) {
			throw new \InvalidArgumentException('Not an indexed key column: ' . $column);
		}
		if ($values === []) {
			return new AttemptStats();
		}
		$qb = $this->statsQuery();
		$type = $column === 'share_id' ? IQueryBuilder::PARAM_INT_ARRAY : IQueryBuilder::PARAM_STR_ARRAY;
		$qb->where($qb->expr()->in($column, $qb->createNamedParameter($values, $type)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)));
		$this->whereKinds($qb, $kinds);
		return $this->fetchStats($qb);
	}

	/**
	 * Counts over all attempts of the given kinds since a time, instance-wide.
	 *
	 * @param list<AttemptKind> $kinds
	 */
	public function instanceStats(array $kinds, int $since): AttemptStats {
		$qb = $this->statsQuery();
		$qb->where($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)));
		$this->whereKinds($qb, $kinds);
		return $this->fetchStats($qb);
	}

	/**
	 * The distinct ip keys among attempts where `$column` matches, at most `$limit`.
	 *
	 * @param 'ip_key'|'net_key'|'pw_fp'|'uid'|'share_id'|'name_hmac' $column
	 * @param list<string|int> $values
	 * @param list<AttemptKind> $kinds
	 * @return list<string>
	 */
	public function distinctIpKeys(string $column, array $values, array $kinds, int $since, int $limit): array {
		if (!in_array($column, self::KEY_COLUMNS, true)) {
			throw new \InvalidArgumentException('Not an indexed key column: ' . $column);
		}
		if ($values === []) {
			return [];
		}
		$qb = $this->db->getQueryBuilder();
		$type = $column === 'share_id' ? IQueryBuilder::PARAM_INT_ARRAY : IQueryBuilder::PARAM_STR_ARRAY;
		$qb->selectDistinct('ip_key')
			->from(self::TABLE)
			->where($qb->expr()->in($column, $qb->createNamedParameter($values, $type)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->setMaxResults($limit);
		$this->whereKinds($qb, $kinds);
		$result = $qb->executeQuery();
		$keys = array_map('strval', $result->fetchFirstColumn());
		$result->closeCursor();
		return $keys;
	}

	/**
	 * The distinct existing accounts among attempts where `$column` matches,
	 * at most `$limit`, for the targets an explanation lists.
	 *
	 * @param 'ip_key'|'net_key'|'pw_fp'|'uid'|'share_id'|'name_hmac' $column
	 * @param list<string|int> $values
	 * @param list<AttemptKind> $kinds
	 * @return list<string>
	 */
	public function distinctUids(string $column, array $values, array $kinds, int $since, int $limit): array {
		if (!in_array($column, self::KEY_COLUMNS, true)) {
			throw new \InvalidArgumentException('Not an indexed key column: ' . $column);
		}
		if ($values === []) {
			return [];
		}
		$qb = $this->db->getQueryBuilder();
		$type = $column === 'share_id' ? IQueryBuilder::PARAM_INT_ARRAY : IQueryBuilder::PARAM_STR_ARRAY;
		$qb->selectDistinct('uid')
			->from(self::TABLE)
			->where($qb->expr()->in($column, $qb->createNamedParameter($values, $type)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->isNotNull('uid'))
			->setMaxResults($limit);
		$this->whereKinds($qb, $kinds);
		$result = $qb->executeQuery();
		$uids = array_map('strval', $result->fetchFirstColumn());
		$result->closeCursor();
		sort($uids);
		return $uids;
	}

	/**
	 * The raw attempts of one source, newest first, for "Show attempts".
	 *
	 * @return list<array{kind: int, uid: ?string, created_at: int}>
	 */
	public function recentForSource(string $ipKey, int $since, int $limit = 100): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('kind', 'uid', 'created_at')
			->from(self::TABLE)
			->where($qb->expr()->eq('ip_key', $qb->createNamedParameter($ipKey)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->orderBy('created_at', 'DESC')
			->setMaxResults($limit);
		$result = $qb->executeQuery();
		$rows = [];
		while ($row = $result->fetch()) {
			$rows[] = ['kind' => (int)$row['kind'], 'uid' => $row['uid'] === null ? null : (string)$row['uid'], 'created_at' => (int)$row['created_at']];
		}
		$result->closeCursor();
		return $rows;
	}

	public function deleteOlderThan(int $before): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->lt('created_at', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement();
	}

	public function deleteForUser(string $uid): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		return $qb->executeStatement();
	}

	/**
	 * Counts over the attempts of one source on one share, for "this address
	 * guessed the password of this share". Uses the ip_key index; the share
	 * is a filter on the few rows of one address.
	 *
	 * @param list<AttemptKind> $kinds
	 */
	public function statsForSourceOnShare(string $ipKey, int $shareId, array $kinds, int $since): AttemptStats {
		$qb = $this->statsQuery();
		$qb->where($qb->expr()->eq('ip_key', $qb->createNamedParameter($ipKey)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('share_id', $qb->createNamedParameter($shareId, IQueryBuilder::PARAM_INT)));
		$this->whereKinds($qb, $kinds);
		return $this->fetchStats($qb);
	}

	/**
	 * Distinct name fingerprints per ip key for one value of a key column,
	 * for "block every address of the network that tried at least N names".
	 *
	 * @param 'ip_key'|'net_key'|'pw_fp'|'uid'|'share_id'|'name_hmac' $column
	 * @param list<AttemptKind> $kinds
	 * @return array<string, int> distinct names per ip key
	 */
	public function distinctNamesPerSource(string $column, string|int $value, array $kinds, int $since, int $limit = 500): array {
		if (!in_array($column, self::KEY_COLUMNS, true)) {
			throw new \InvalidArgumentException('Not an indexed key column: ' . $column);
		}
		$qb = $this->db->getQueryBuilder();
		$qb->select('ip_key')
			->selectAlias($qb->createFunction('COUNT(DISTINCT ' . $qb->getColumnName('name_hmac') . ')'), 'n')
			->from(self::TABLE)
			->where($qb->expr()->eq($column, $qb->createNamedParameter($value, is_int($value) ? IQueryBuilder::PARAM_INT : IQueryBuilder::PARAM_STR)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->groupBy('ip_key')
			->setMaxResults($limit);
		$this->whereKinds($qb, $kinds);
		$result = $qb->executeQuery();
		$counts = [];
		while ($row = $result->fetch()) {
			$counts[(string)$row['ip_key']] = (int)$row['n'];
		}
		$result->closeCursor();
		return $counts;
	}

	/**
	 * Per source among attempts where `$column` matches: the failures, the
	 * different login names and the different passwords (by fingerprint),
	 * for deciding which further addresses a detection may block.
	 *
	 * @param 'ip_key'|'net_key'|'pw_fp'|'uid'|'share_id'|'name_hmac' $column
	 * @param list<string|int> $values
	 * @param list<AttemptKind> $kinds
	 * @return array<string, array{failures: int, names: int, passwords: int}> keyed by ip key
	 */
	public function countsPerSource(string $column, array $values, array $kinds, int $since, int $limit = 500): array {
		if (!in_array($column, self::KEY_COLUMNS, true)) {
			throw new \InvalidArgumentException('Not an indexed key column: ' . $column);
		}
		if ($values === []) {
			return [];
		}
		$qb = $this->db->getQueryBuilder();
		$type = $column === 'share_id' ? IQueryBuilder::PARAM_INT_ARRAY : IQueryBuilder::PARAM_STR_ARRAY;
		$qb->select('ip_key')
			->selectAlias($qb->func()->count('*'), 'failures')
			->selectAlias($qb->createFunction('COUNT(DISTINCT ' . $qb->getColumnName('name_hmac') . ')'), 'names')
			->selectAlias($qb->createFunction('COUNT(DISTINCT ' . $qb->getColumnName('pw_fp') . ')'), 'passwords')
			->from(self::TABLE)
			->where($qb->expr()->in($column, $qb->createNamedParameter($values, $type)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->groupBy('ip_key')
			->setMaxResults($limit);
		$this->whereKinds($qb, $kinds);
		$result = $qb->executeQuery();
		$counts = [];
		while ($row = $result->fetch()) {
			$counts[(string)$row['ip_key']] = ['failures' => (int)$row['failures'], 'names' => (int)$row['names'], 'passwords' => (int)$row['passwords']];
		}
		$result->closeCursor();
		return $counts;
	}

	/**
	 * A query for the counts of {@see AttemptStats}, without conditions.
	 */
	private function statsQuery(): IQueryBuilder {
		$qb = $this->db->getQueryBuilder();
		$weight = $qb->getColumnName('weight');
		$name = $qb->getColumnName('name_hmac');
		$qb->select($qb->func()->count('*', 'failures'))
			->selectAlias($qb->func()->sum('weight'), 'weighted')
			->selectAlias($qb->func()->max('weight'), 'max_weight')
			->selectAlias($qb->createFunction('COUNT(DISTINCT CASE WHEN ' . $weight . ' > 1 THEN ' . $name . ' END)'), 'sampled_names')
			->selectAlias($qb->createFunction('COUNT(DISTINCT ' . $qb->getColumnName('name_hmac') . ')'), 'names')
			->selectAlias($qb->createFunction('COUNT(DISTINCT ' . $qb->getColumnName('ip_key') . ')'), 'sources')
			->selectAlias($qb->createFunction('COUNT(DISTINCT ' . $qb->getColumnName('uid') . ')'), 'users')
			->selectAlias($qb->func()->min('created_at'), 'first')
			->selectAlias($qb->func()->max('created_at'), 'last')
			->from(self::TABLE);
		return $qb;
	}

	/**
	 * @param list<AttemptKind> $kinds
	 */
	private function whereKinds(IQueryBuilder $qb, array $kinds): void {
		if ($kinds !== []) {
			$qb->andWhere($qb->expr()->in('kind', $qb->createNamedParameter(
				array_map(static fn (AttemptKind $k): int => $k->value, $kinds),
				IQueryBuilder::PARAM_INT_ARRAY,
			)));
		}
	}

	private function fetchStats(IQueryBuilder $qb): AttemptStats {
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		if ($row === false) {
			return new AttemptStats();
		}
		$names = (int)$row['names'];
		$sampledNames = (int)($row['sampled_names'] ?? 0);
		$maxWeight = max(1, (int)($row['max_weight'] ?? 1));
		return new AttemptStats(
			failures: (int)$row['failures'],
			distinctNames: $names,
			distinctSources: (int)$row['sources'],
			distinctUsers: (int)$row['users'],
			first: (int)($row['first'] ?? 0),
			last: (int)($row['last'] ?? 0),
			estimatedFailures: (int)($row['weighted'] ?? $row['failures']),
			// Names seen in sampled rows stand for `maxWeight` names each; only one sample rate exists.
			estimatedNames: $names - $sampledNames + $sampledNames * $maxWeight,
			maxWeight: $maxWeight,
		);
	}
}
