<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

/**
 * The lists the app knows out of the box. All are off until an administrator
 * switches them on. Their address, format and purpose are fixed here; the
 * administrator only chooses whether they are on, the mode and the interval.
 */
final class BuiltinSources {
	/**
	 * @return array<string, BlocklistSource> keyed by id
	 */
	public static function all(): array {
		$list = [
			new BlocklistSource(
				'spamhaus_drop_v4', 'Spamhaus DROP (IPv4)', 'https://www.spamhaus.org/drop/drop_v4.json',
				ListFormat::SpamhausJson, BlocklistSource::PURPOSE_DENY, BlocklistSource::MODE_PROTECT, false, null, true,
				'https://www.spamhaus.org/drop/terms/',
			),
			new BlocklistSource(
				'spamhaus_drop_v6', 'Spamhaus DROP (IPv6)', 'https://www.spamhaus.org/drop/drop_v6.json',
				ListFormat::SpamhausJson, BlocklistSource::PURPOSE_DENY, BlocklistSource::MODE_PROTECT, false, null, true,
				'https://www.spamhaus.org/drop/terms/',
			),
			new BlocklistSource(
				'firehol_level1', 'FireHOL level 1', 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
				ListFormat::Cidr, BlocklistSource::PURPOSE_DENY, BlocklistSource::MODE_PROTECT, false, null, true,
				'https://iplists.firehol.org/?ipset=firehol_level1',
			),
			new BlocklistSource(
				'aws', 'Amazon Web Services', 'https://ip-ranges.amazonaws.com/ip-ranges.json',
				ListFormat::AwsJson, BlocklistSource::PURPOSE_HOSTING, null, false, null, true,
				'https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html',
			),
			new BlocklistSource(
				'google_cloud', 'Google Cloud', 'https://www.gstatic.com/ipranges/cloud.json',
				ListFormat::GoogleJson, BlocklistSource::PURPOSE_HOSTING, null, false, null, true,
				'https://cloud.google.com/compute/docs/faq#find_ip_range',
			),
			new BlocklistSource(
				'oracle_cloud', 'Oracle Cloud', 'https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json',
				ListFormat::OracleJson, BlocklistSource::PURPOSE_HOSTING, null, false, null, true,
				'https://docs.oracle.com/en-us/iaas/Content/General/Concepts/addressranges.htm',
			),
			new BlocklistSource(
				'digitalocean', 'DigitalOcean', 'https://www.digitalocean.com/geo/google.csv',
				ListFormat::GeofeedCsv, BlocklistSource::PURPOSE_HOSTING, null, false, null, true,
				'https://docs.digitalocean.com/platform/',
			),
			new BlocklistSource(
				'tor_exits', 'Tor exit nodes', 'https://check.torproject.org/torbulkexitlist',
				ListFormat::Cidr, BlocklistSource::PURPOSE_TOR, null, false, 3600, true,
				'https://metrics.torproject.org/',
			),
		];
		$byId = [];
		foreach ($list as $source) {
			$byId[$source->id] = $source;
		}
		return $byId;
	}
}
