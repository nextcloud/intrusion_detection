<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist\Parser;

/**
 * Plain text: one range or address per line. `#` and `;` start a comment,
 * blank lines are ignored. A line with anything besides one range is
 * malformed. Used for custom lists, FireHOL and the Tor exit list.
 */
class CidrTextParser implements IListParser {
	#[\Override]
	public function parse(string $body, int $maxEntries = PHP_INT_MAX): ParsedList {
		$list = new ParsedList($maxEntries);
		foreach (Lines::of($body) as $line) {
			$cut = strcspn($line, '#;');
			$line = trim(substr($line, 0, $cut));
			if ($line !== '') {
				$list->add(preg_match('/\s/', $line) ? '' : $line);
			}
		}
		return $list;
	}
}
