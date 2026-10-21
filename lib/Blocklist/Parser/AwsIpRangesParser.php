<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist\Parser;

/**
 * AWS ip-ranges.json: `prefixes[].ip_prefix` and `ipv6_prefixes[].ipv6_prefix`.
 * Every service is read; the service `AMAZON` already contains the others,
 * and the duplicates are merged away.
 */
class AwsIpRangesParser implements IListParser {
	#[\Override]
	public function parse(string $body): ParsedList {
		$data = JsonDocument::decode($body);
		if (!isset($data['prefixes']) && !isset($data['ipv6_prefixes'])) {
			throw new ListFormatException('Not an AWS ip-ranges document');
		}
		$list = new ParsedList();
		JsonDocument::collect($list, $data['prefixes'] ?? null, 'ip_prefix');
		JsonDocument::collect($list, $data['ipv6_prefixes'] ?? null, 'ipv6_prefix');
		return $list;
	}
}
