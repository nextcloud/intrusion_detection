<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Export;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;

/**
 * Configuration snippets the admin page shows next to the firewall export,
 * filled in with this server's export directory.
 *
 * The export files are written by the web server user and read by root. The
 * loaders therefore check every line of a file against the exact grammar the
 * app writes ({@see self::NFT_LINE_PATTERN}, {@see self::IPSET_LINE_PATTERN})
 * before loading it, so whoever can write the files can fill the app's own
 * sets, but cannot run any other firewall command.
 */
class FirewallSnippets {
	/** Used in the snippets while no directory is configured, or when its path needs quoting */
	public const EXAMPLE_DIR = '/var/lib/nextcloud-ids';

	/** Every line of bans.nft matches this (POSIX extended and PCRE) */
	public const NFT_LINE_PATTERN = '^(#.*|table inet nextcloud_ids [{]|[[:space:]]+set banned_v[46] [{]|[[:space:]]+type ipv[46]_addr|[[:space:]]+flags interval, timeout|[[:space:]]*[}]|flush set inet nextcloud_ids banned_v[46]|add element inet nextcloud_ids banned_v[46] [{] [0-9a-f.:/]+ timeout [0-9]+s(, [0-9a-f.:/]+ timeout [0-9]+s)* [}])$';

	/** Every line of bans.ipset matches this (POSIX extended and PCRE) */
	public const IPSET_LINE_PATTERN = '^(#.*|create nextcloud_ids_v[46](_new)? hash:net family inet6? timeout 0 -exist|flush nextcloud_ids_v[46]_new|add nextcloud_ids_v[46]_new [0-9a-f.:/]+ timeout [0-9]+|swap nextcloud_ids_v[46]_new nextcloud_ids_v[46]|destroy nextcloud_ids_v[46]_new)$';

	/** The fail2ban filter's failregex; fail2ban removes the time stamp before matching */
	public const FAIL2BAN_FAILREGEX = '^\s*BAN <SUBNET> until=\S+ level=\d+ check=[a-z0-9_]+ ref=[A-Z0-9]+\s*$';

	/** The fail2ban filter's datepattern, `%` doubled as fail2ban's configuration files require */
	public const FAIL2BAN_DATEPATTERN = '{^LN-BEG}%%Y-%%m-%%dT%%H:%%M:%%SZ';

	public function __construct(
		private readonly ExportDirectory $directory,
		private readonly Settings $settings,
	) {
	}

	/**
	 * Every snippet, keyed by a stable name, with the file it belongs in.
	 *
	 * @return array<string, array{file: string, content: string}>
	 */
	public function all(): array {
		return [
			'nftables' => ['file' => '/etc/nftables.d/nextcloud-ids.nft', 'content' => $this->nftables()],
			'nft_loader' => ['file' => '/usr/local/sbin/nextcloud-ids-load', 'content' => $this->nftLoader()],
			'systemd_path' => ['file' => '/etc/systemd/system/nextcloud-ids-firewall.path', 'content' => $this->systemdPath()],
			'systemd_service' => ['file' => '/etc/systemd/system/nextcloud-ids-firewall.service', 'content' => $this->systemdService()],
			'ipset' => ['file' => '/usr/local/sbin/nextcloud-ids-load-ipset', 'content' => $this->ipset()],
			'fail2ban_filter' => ['file' => '/etc/fail2ban/filter.d/nextcloud-ids.conf', 'content' => $this->fail2banFilter()],
			'fail2ban_jail' => ['file' => '/etc/fail2ban/jail.d/nextcloud-ids.local', 'content' => $this->fail2banJail()],
		];
	}

	/**
	 * Whether the snippets use the configured directory. False when none is
	 * configured, or when its path has characters that would need quoting in
	 * unit files; the snippets then show {@see self::EXAMPLE_DIR}.
	 */
	public function usesConfiguredDirectory(): bool {
		$dir = $this->directory->configured();
		return $dir !== null && preg_match('#^/[A-Za-z0-9/._-]+$#', $dir) === 1;
	}

	/**
	 * The table, sets and chain, loaded once with the system's nftables rules.
	 */
	public function nftables(): string {
		return <<<'NFT'
			# Nextcloud intrusion detection: drop web traffic from blocked addresses.
			# The sets are filled from bans.nft by nextcloud-ids-load.
			table inet nextcloud_ids {
				set banned_v4 {
					type ipv4_addr
					flags interval, timeout
				}
				set banned_v6 {
					type ipv6_addr
					flags interval, timeout
				}
				chain input {
					type filter hook input priority filter - 10; policy accept;
					ip saddr @banned_v4 tcp dport { 80, 443 } drop
					ip6 saddr @banned_v6 tcp dport { 80, 443 } drop
				}
			}

			NFT;
	}

	/**
	 * A root-owned script that loads bans.nft after checking every line.
	 */
	public function nftLoader(): string {
		$file = $this->dir() . '/bans.nft';
		$pattern = self::NFT_LINE_PATTERN;
		return <<<SH
			#!/bin/sh
			# Loads the blocks Nextcloud wrote, after checking that the file only
			# fills the nextcloud_ids sets. Install as root, mode 0755.
			set -eu
			file='{$file}'
			[ -f "\$file" ] || exit 0
			if grep -Evq '{$pattern}' "\$file"; then
				logger -t nextcloud-ids "refusing \$file: unexpected content"
				exit 1
			fi
			exec /usr/sbin/nft -f "\$file"

			SH;
	}

	/**
	 * Runs the loader whenever Nextcloud replaces bans.nft.
	 */
	public function systemdPath(): string {
		$file = $this->dir() . '/bans.nft';
		return <<<UNIT
			[Unit]
			Description=Load Nextcloud intrusion detection blocks when they change

			[Path]
			PathChanged={$file}
			Unit=nextcloud-ids-firewall.service

			[Install]
			WantedBy=multi-user.target

			UNIT;
	}

	public function systemdService(): string {
		return <<<'UNIT'
			[Unit]
			Description=Load Nextcloud intrusion detection blocks into nftables
			After=nftables.service

			[Service]
			Type=oneshot
			ExecStart=/usr/local/sbin/nextcloud-ids-load

			[Install]
			WantedBy=multi-user.target

			UNIT;
	}

	/**
	 * For iptables with ipset: the rules to add once, and a loader for bans.ipset.
	 */
	public function ipset(): string {
		$file = $this->dir() . '/bans.ipset';
		$pattern = self::IPSET_LINE_PATTERN;
		return <<<SH
			#!/bin/sh
			# Loads the blocks Nextcloud wrote into ipset, after checking every line.
			# Add the firewall rules once, as root:
			#   ipset create nextcloud_ids_v4 hash:net family inet timeout 0 -exist
			#   ipset create nextcloud_ids_v6 hash:net family inet6 timeout 0 -exist
			#   iptables -I INPUT -p tcp -m multiport --dports 80,443 -m set --match-set nextcloud_ids_v4 src -j DROP
			#   ip6tables -I INPUT -p tcp -m multiport --dports 80,443 -m set --match-set nextcloud_ids_v6 src -j DROP
			# Then run this script from a systemd path unit or every minute from cron.
			set -eu
			file='{$file}'
			[ -f "\$file" ] || exit 0
			if grep -Evq '{$pattern}' "\$file"; then
				logger -t nextcloud-ids "refusing \$file: unexpected content"
				exit 1
			fi
			exec /usr/sbin/ipset restore < "\$file"

			SH;
	}

	public function fail2banFilter(): string {
		$failregex = self::FAIL2BAN_FAILREGEX;
		$datepattern = self::FAIL2BAN_DATEPATTERN;
		return <<<CONF
			# Nextcloud intrusion detection: blocks from bans.log (needs fail2ban 0.10 or later).
			# Only BAN lines are matched; a lifted block stays in fail2ban until its ban time ends,
			# or until you run: fail2ban-client set nextcloud-ids unbanip <address>
			[Definition]
			failregex = {$failregex}
			ignoreregex =
			datepattern = {$datepattern}

			CONF;
	}

	/**
	 * The jail. fail2ban uses one ban time for all; it is set to the app's
	 * first block duration.
	 */
	public function fail2banJail(): string {
		$file = $this->dir() . '/bans.log';
		$bantime = $this->settings->getInt(GlobalSettings::BAN_DURATION_1);
		return <<<CONF
			[nextcloud-ids]
			enabled  = true
			filter   = nextcloud-ids
			logpath  = {$file}
			port     = http,https
			maxretry = 1
			findtime = 600
			bantime  = {$bantime}

			CONF;
	}

	private function dir(): string {
		return $this->usesConfiguredDirectory() ? rtrim((string)$this->directory->configured(), '/') : self::EXAMPLE_DIR;
	}
}
