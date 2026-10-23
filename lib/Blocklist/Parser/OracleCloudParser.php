<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist\Parser;

/**
 * Oracle Cloud public_ip_ranges.json: `regions[].cidrs[].cidr`.
 */
class OracleCloudParser implements IListParser {
	#[\Override]
	public function parse(string $body, int $maxEntries = PHP_INT_MAX): ParsedList {
		$data = JsonDocument::decode($body);
		if (!isset($data['regions']) || !is_array($data['regions'])) {
			throw new ListFormatException('Not an Oracle Cloud ranges document');
		}
		$list = new ParsedList($maxEntries);
		foreach ($data['regions'] as $region) {
			if (!is_array($region)) {
				$list->malformed++;
				continue;
			}
			JsonDocument::collect($list, $region['cidrs'] ?? null, 'cidr');
		}
		return $list;
	}
}
