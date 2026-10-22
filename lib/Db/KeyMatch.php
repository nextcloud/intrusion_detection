<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCA\IntrusionDetection\Net\Ipv6Networks;
use OCP\DB\QueryBuilder\ICompositeExpression;
use OCP\DB\QueryBuilder\IQueryBuilder;

/**
 * A set of stored keys (addresses, networks), as exact values plus LIKE
 * patterns, for a query condition on one column.
 *
 * The patterns also become a key range: from their common literal prefix
 * up to the prefix followed by RANGE_END (`>= prefix AND < prefix . 'g'`),
 * with the patterns as a filter within it. A btree index can search such a
 * range on every database, a LIKE pattern only where the column sorts byte
 * by byte (not on PostgreSQL with its usual collations). The range holds
 * every key that starts with the prefix: keys are made of digits, the
 * lower-case hex letters a to f, ".", ":" and "/", which all sort below
 * "g" in the binary, C and Unicode collations, and those compare character
 * by character. The filter keeps the result exact.
 */
final class KeyMatch {
	/** Sorts after every character keys are made of */
	public const RANGE_END = 'g';

	/**
	 * @param list<string> $exact keys matched as they are
	 * @param list<string> $patterns LIKE patterns, already escaped where literal
	 */
	public function __construct(
		public readonly array $exact,
		public readonly array $patterns = [],
	) {
	}

	/**
	 * The /64 keys inside a /56 or /48 network key.
	 *
	 * @throws \InvalidArgumentException for any other key
	 */
	public static function slash64sIn(string $networkKey): self {
		[$exact, $patterns] = Ipv6Networks::slash64Keys($networkKey);
		return new self($exact, $patterns);
	}

	public function condition(IQueryBuilder $qb, string $column): ICompositeExpression {
		$parts = [];
		if ($this->exact !== []) {
			$parts[] = $qb->expr()->in($column, $qb->createNamedParameter($this->exact, IQueryBuilder::PARAM_STR_ARRAY));
		}
		if ($this->patterns !== []) {
			$likes = array_map(static fn (string $pattern): string => $qb->expr()->like($column, $qb->createNamedParameter($pattern)), $this->patterns);
			$prefix = $this->prefix();
			$parts[] = $prefix === ''
				? $qb->expr()->orX(...$likes)
				: $qb->expr()->andX(
					$qb->expr()->gte($column, $qb->createNamedParameter($prefix)),
					$qb->expr()->lt($column, $qb->createNamedParameter($prefix . self::RANGE_END)),
					$qb->expr()->orX(...$likes),
				);
		}
		return $qb->expr()->orX(...$parts);
	}

	/**
	 * The longest literal start all patterns share: each up to its first
	 * wildcard or escape character.
	 */
	public function prefix(): string {
		$prefix = null;
		foreach ($this->patterns as $pattern) {
			$literal = substr($pattern, 0, strcspn($pattern, '%_\\'));
			if ($prefix === null) {
				$prefix = $literal;
				continue;
			}
			$length = 0;
			$max = min(strlen($prefix), strlen($literal));
			while ($length < $max && $prefix[$length] === $literal[$length]) {
				$length++;
			}
			$prefix = substr($prefix, 0, $length);
		}
		return $prefix ?? '';
	}
}
