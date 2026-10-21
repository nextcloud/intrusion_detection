<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Export;

use OCA\IntrusionDetection\Db\Ban;

/**
 * The contents of the export files. Pure functions of the active blocks and
 * the time, so they can be compared with golden files.
 *
 * Firewalls get the remaining time of each block as its timeout, so an entry
 * drops out by itself when the block ends, even if no new file is written.
 */
final class ExportRenderer {
	public const NFT_TABLE = 'inet nextcloud_ids';
	public const NFT_SET_V4 = 'banned_v4';
	public const NFT_SET_V6 = 'banned_v6';
	public const IPSET_V4 = 'nextcloud_ids_v4';
	public const IPSET_V6 = 'nextcloud_ids_v6';
	/** The longest timeout ipset accepts, in seconds */
	public const IPSET_MAX_TIMEOUT = 2147483;
	/** Elements per nftables `add element` line */
	private const NFT_CHUNK = 500;

	/**
	 * @param list<ExportEntry> $entries sorted ({@see ExportEntry::sort()})
	 */
	public static function render(ExportFormat $format, array $entries, int $now): string {
		return match ($format) {
			ExportFormat::Txt => self::txt($entries, $now),
			ExportFormat::Nft => self::nft($entries, $now),
			ExportFormat::Ipset => self::ipset($entries, $now),
			ExportFormat::Log => '',
		};
	}

	/**
	 * @param list<ExportEntry> $entries
	 */
	public static function txt(array $entries, int $now): string {
		$out = '# Nextcloud intrusion detection: active blocks, written ' . self::time($now) . ".\n"
			. "# One range per line. The comment gives the end of the block and its reference.\n";
		foreach ($entries as $entry) {
			$out .= $entry->cidr . ' # until=' . self::time($entry->expiresAt) . ' ref=' . $entry->reference . "\n";
		}
		return $out;
	}

	/**
	 * @param list<ExportEntry> $entries
	 */
	public static function nft(array $entries, int $now): string {
		$out = "#!/usr/sbin/nft -f\n"
			. '# Nextcloud intrusion detection: active blocks, written ' . self::time($now) . ".\n"
			. "# Generated file. Load it with: nft -f bans.nft\n"
			. 'table ' . self::NFT_TABLE . " {\n"
			. "\tset " . self::NFT_SET_V4 . " {\n\t\ttype ipv4_addr\n\t\tflags interval, timeout\n\t}\n"
			. "\tset " . self::NFT_SET_V6 . " {\n\t\ttype ipv6_addr\n\t\tflags interval, timeout\n\t}\n"
			. "}\n"
			. 'flush set ' . self::NFT_TABLE . ' ' . self::NFT_SET_V4 . "\n"
			. 'flush set ' . self::NFT_TABLE . ' ' . self::NFT_SET_V6 . "\n";
		$entries = ExportEntry::disjoint($entries);
		foreach ([4 => self::NFT_SET_V4, 6 => self::NFT_SET_V6] as $family => $set) {
			$elements = [];
			foreach ($entries as $entry) {
				if ($entry->family === $family) {
					$elements[] = $entry->cidr . ' timeout ' . max(1, $entry->expiresAt - $now) . 's';
				}
			}
			foreach (array_chunk($elements, self::NFT_CHUNK) as $chunk) {
				$out .= 'add element ' . self::NFT_TABLE . ' ' . $set . ' { ' . implode(', ', $chunk) . " }\n";
			}
		}
		return $out;
	}

	/**
	 * Fills a temporary set and swaps it in, so the live set is never empty
	 * while it is reloaded.
	 *
	 * @param list<ExportEntry> $entries
	 */
	public static function ipset(array $entries, int $now): string {
		$out = '# Nextcloud intrusion detection: active blocks, written ' . self::time($now) . ".\n"
			. "# Generated file. Load it with: ipset restore < bans.ipset\n";
		foreach ([4 => self::IPSET_V4, 6 => self::IPSET_V6] as $family => $set) {
			$inet = $family === 4 ? 'inet' : 'inet6';
			$out .= 'create ' . $set . ' hash:net family ' . $inet . " timeout 0 -exist\n"
				. 'create ' . $set . '_new hash:net family ' . $inet . " timeout 0 -exist\n"
				. 'flush ' . $set . "_new\n";
			foreach ($entries as $entry) {
				if ($entry->family === $family) {
					$out .= 'add ' . $set . '_new ' . $entry->cidr . ' timeout ' . min(self::IPSET_MAX_TIMEOUT, max(1, $entry->expiresAt - $now)) . "\n";
				}
			}
			$out .= 'swap ' . $set . '_new ' . $set . "\n"
				. 'destroy ' . $set . "_new\n";
		}
		return $out;
	}

	/**
	 * The fail2ban log line for a new or raised block.
	 */
	public static function banLine(Ban $ban, int $now): string {
		return self::time($now) . ' BAN ' . $ban->getCidr()
			. ' until=' . self::time($ban->getExpiresAt())
			. ' level=' . $ban->getLevel()
			. ' check=' . $ban->getCheckId()
			. ' ref=' . $ban->getReference() . "\n";
	}

	/**
	 * The log line for a block lifted before it ended. fail2ban ignores it.
	 */
	public static function liftLine(Ban $ban, int $now): string {
		return self::time($now) . ' LIFT ' . $ban->getCidr() . ' ref=' . $ban->getReference() . "\n";
	}

	public static function time(int $timestamp): string {
		return gmdate('Y-m-d\TH:i:s\Z', $timestamp);
	}
}
