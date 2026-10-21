<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist\Parser;

/**
 * Google Cloud cloud.json: `prefixes[]` with either `ipv4Prefix` or `ipv6Prefix`.
 */
class GoogleCloudParser implements IListParser {
	#[\Override]
	public function parse(string $body): ParsedList {
		$data = JsonDocument::decode($body);
		if (!isset($data['prefixes']) || !is_array($data['prefixes'])) {
			throw new ListFormatException('Not a Google Cloud ranges document');
		}
		$list = new ParsedList();
		foreach ($data['prefixes'] as $prefix) {
			$value = is_array($prefix) ? ($prefix['ipv4Prefix'] ?? $prefix['ipv6Prefix'] ?? null) : null;
			$list->add(is_string($value) ? $value : '');
		}
		return $list;
	}
}
