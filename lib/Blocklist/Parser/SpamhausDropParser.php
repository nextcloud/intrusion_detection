<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist\Parser;

/**
 * Spamhaus DROP in JSON (drop_v4.json, drop_v6.json): one JSON object per
 * line, `{"cidr":"192.0.2.0/24","sblid":"SBL123","rir":"arin"}`, and a final
 * `{"type":"metadata",…}` line.
 */
class SpamhausDropParser implements IListParser {
	#[\Override]
	public function parse(string $body): ParsedList {
		$list = new ParsedList();
		$objects = 0;
		foreach (Lines::of($body) as $line) {
			$line = trim($line);
			if ($line === '') {
				continue;
			}
			$entry = json_decode($line, true, 4);
			if (!is_array($entry)) {
				$list->malformed++;
				continue;
			}
			$objects++;
			if (($entry['type'] ?? null) === 'metadata') {
				continue;
			}
			$list->add(is_string($entry['cidr'] ?? null) ? $entry['cidr'] : '');
		}
		if ($objects === 0) {
			throw new ListFormatException('No JSON lines');
		}
		return $list;
	}
}
