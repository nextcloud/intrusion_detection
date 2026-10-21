<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

use OCA\IntrusionDetection\Blocklist\Parser\AwsIpRangesParser;
use OCA\IntrusionDetection\Blocklist\Parser\CidrTextParser;
use OCA\IntrusionDetection\Blocklist\Parser\GeofeedCsvParser;
use OCA\IntrusionDetection\Blocklist\Parser\GoogleCloudParser;
use OCA\IntrusionDetection\Blocklist\Parser\IListParser;
use OCA\IntrusionDetection\Blocklist\Parser\OracleCloudParser;
use OCA\IntrusionDetection\Blocklist\Parser\SpamhausDropParser;

/**
 * The file formats the app can read.
 */
enum ListFormat: string {
	/** One range or address per line; `#` and `;` start a comment */
	case Cidr = 'cidr';
	/** Spamhaus DROP: one JSON object per line with a `cidr` field */
	case SpamhausJson = 'spamhaus_json';
	/** AWS ip-ranges.json */
	case AwsJson = 'aws_json';
	/** Google Cloud cloud.json */
	case GoogleJson = 'google_json';
	/** Oracle Cloud public_ip_ranges.json */
	case OracleJson = 'oracle_json';
	/** RFC 8805 geofeed CSV, the range in the first column (DigitalOcean) */
	case GeofeedCsv = 'geofeed_csv';

	public function parser(): IListParser {
		return match ($this) {
			self::Cidr => new CidrTextParser(),
			self::SpamhausJson => new SpamhausDropParser(),
			self::AwsJson => new AwsIpRangesParser(),
			self::GoogleJson => new GoogleCloudParser(),
			self::OracleJson => new OracleCloudParser(),
			self::GeofeedCsv => new GeofeedCsvParser(),
		};
	}
}
