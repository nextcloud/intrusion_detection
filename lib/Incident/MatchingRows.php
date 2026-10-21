<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

/**
 * Rows a query can only narrow down roughly, checked one by one afterwards.
 * Pages are read until enough rows matched, the query has no more, or
 * MAX_PAGES were read, so that a source never returns fewer rows than exist
 * only because some of a page did not match, and the work for one source
 * stays bounded. Pages continue after the last row of the previous page
 * (keyset paging), so a later page costs no more than the first.
 */
final class MatchingRows {
	/** Pages read at most, as a bound on the work for one source */
	public const MAX_PAGES = 20;

	/**
	 * @template T
	 * @param \Closure(?T $after, int $limit): list<T> $page one page of the query after a row (null: from the start), oldest first
	 * @param \Closure(T): bool $matches whether a row really matches
	 * @return list<T> at most `$limit` matching rows, oldest first
	 */
	public static function collect(\Closure $page, \Closure $matches, int $limit): array {
		$found = [];
		$after = null;
		for ($pages = 0; $pages < self::MAX_PAGES; $pages++) {
			$rows = $page($after, $limit);
			foreach ($rows as $row) {
				if ($matches($row)) {
					$found[] = $row;
					if (count($found) >= $limit) {
						return $found;
					}
				}
			}
			$last = end($rows);
			if (count($rows) < $limit || $last === false) {
				break;
			}
			$after = $last;
		}
		return $found;
	}
}
