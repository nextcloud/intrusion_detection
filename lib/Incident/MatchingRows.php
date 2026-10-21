<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

/**
 * Rows a query can only narrow down roughly (a LIKE on JSON), checked one
 * by one afterwards. Pages are read until enough rows matched or the query
 * has no more, so that a source never returns fewer rows than exist only
 * because some of a page did not match. The report could not tell that it
 * is incomplete otherwise.
 */
final class MatchingRows {
	/** Pages read at most, as a bound on the work for one source */
	public const MAX_PAGES = 20;

	/**
	 * @template T
	 * @param \Closure(int $offset, int $limit): list<T> $page one page of the query, oldest first
	 * @param \Closure(T): bool $matches whether a row really matches
	 * @return list<T> at most `$limit` matching rows, oldest first
	 */
	public static function collect(\Closure $page, \Closure $matches, int $limit): array {
		$found = [];
		for ($offset = 0; ; $offset += $limit) {
			$rows = $page($offset, $limit);
			foreach ($rows as $row) {
				if ($matches($row)) {
					$found[] = $row;
					if (count($found) >= $limit) {
						return $found;
					}
				}
			}
			if (count($rows) < $limit) {
				return $found;
			}
		}
	}
}
