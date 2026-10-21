<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCP\DB\QueryBuilder\ICompositeExpression;
use OCP\DB\QueryBuilder\IQueryBuilder;

/**
 * A set of stored keys (addresses, networks), as exact values plus LIKE
 * patterns, for a query condition on one column.
 */
final class KeyMatch {
	/**
	 * @param list<string> $exact keys matched as they are
	 * @param list<string> $patterns LIKE patterns, already escaped where literal
	 */
	public function __construct(
		public readonly array $exact,
		public readonly array $patterns = [],
	) {
	}

	public function condition(IQueryBuilder $qb, string $column): ICompositeExpression {
		$parts = [];
		if ($this->exact !== []) {
			$parts[] = $qb->expr()->in($column, $qb->createNamedParameter($this->exact, IQueryBuilder::PARAM_STR_ARRAY));
		}
		foreach ($this->patterns as $pattern) {
			$parts[] = $qb->expr()->like($column, $qb->createNamedParameter($pattern));
		}
		return $qb->expr()->orX(...$parts);
	}
}
