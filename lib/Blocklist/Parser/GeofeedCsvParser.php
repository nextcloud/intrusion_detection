<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist\Parser;

/**
 * An RFC 8805 geofeed, as DigitalOcean publishes its ranges:
 * `ip_prefix,country,region,city,postal_code`, `#` starts a comment.
 */
class GeofeedCsvParser implements IListParser {
	#[\Override]
	public function parse(string $body, int $maxEntries = PHP_INT_MAX): ParsedList {
		$list = new ParsedList($maxEntries);
		foreach (Lines::of($body) as $line) {
			$line = trim($line);
			if ($line === '' || $line[0] === '#') {
				continue;
			}
			$list->add(trim(explode(',', $line, 2)[0]));
		}
		return $list;
	}
}
