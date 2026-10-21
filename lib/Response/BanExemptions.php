<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\KeyMatch;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Net\ProtectedRanges;
use OCA\IntrusionDetection\Net\ProxySuspect;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IGroupManager;

/**
 * Why an address or network must not be blocked automatically, asked only
 * when a block is about to be created (never on the common path):
 *
 * - Safety valve: at least BAN_SHARED_IP_USERS different people logged in
 *   successfully from the address (for a network: from the network) within
 *   24 hours. An office network or a reverse proxy.
 * - Unconfigured reverse proxy: a private address most of the latest logins
 *   of different people came from, while no trusted proxy is configured
 *   ({@see ProxySuspect}).
 * - Its owners: within TRUSTED_LOGIN_DAYS someone confirmed a login from it
 *   (a second factor, an email code, admin approval or a remembered device),
 *   or an administrator logged in from it. Such an address is used by people
 *   of this server, and requests from it that look like attacks are more
 *   likely caused by a web page or a misconfigured client than by them.
 *   Blocks by hand still work.
 * - For networks also: the network contains loopback, the server's own
 *   address or an address on the brute-force allowlist.
 */
class BanExemptions {
	public const TRUSTED_LOGIN_DAYS = 7;
	/** At most this many recent logins are looked at for an address or network */
	private const TRUSTED_LOGIN_ROWS = 50;

	public function __construct(
		private readonly LoginMapper $logins,
		private readonly LoginHistoryMapper $history,
		private readonly Settings $settings,
		private readonly ProxySuspect $proxies,
		private readonly ProtectedRanges $protected,
		private readonly IGroupManager $groups,
	) {
	}

	/**
	 * Why one address (an IPv4 address, an IPv6 /64) must not be blocked
	 * now, or null when it may be.
	 */
	public function forAddress(SourceKey $source, int $now): ?BanResult {
		$shared = $this->sharedUsers($this->logins->distinctUsersForIp($source->ipKey, intdiv($now - 86400, 3600)));
		if ($shared > 0) {
			return new BanResult(BanResult::SKIPPED_SHARED, sharedUsers: $shared);
		}
		$behind = $this->proxies->accountsBehind($source);
		if ($behind > 0) {
			return new BanResult(BanResult::SKIPPED_PROXY, sharedUsers: $behind);
		}
		$trusted = $source->family === 4
			? $this->hasTrustedLogin('ip', new KeyMatch([$source->ip]), $now)
			: $this->hasTrustedLogin('net_key', new KeyMatch([$source->ipKey]), $now);
		return $trusted ? new BanResult(BanResult::SKIPPED_TRUSTED) : null;
	}

	/**
	 * Why a network must not be blocked now, or null when it may be.
	 *
	 * @param string $cidr the network
	 * @param KeyMatch $netKeys its keys as the login tables store them: the /24, or the /64s inside an IPv6 network
	 */
	public function forNetwork(string $cidr, KeyMatch $netKeys, int $now): ?BanResult {
		$range = RangeCodec::parse($cidr);
		if ($this->protected->overlaps($range['family'], $range['start'], $range['end'])) {
			return new BanResult(BanResult::SKIPPED_NEVER);
		}
		$shared = $this->sharedUsers($this->logins->distinctUsersForNets($netKeys, intdiv($now - 86400, 3600)));
		if ($shared > 0) {
			return new BanResult(BanResult::SKIPPED_SHARED, sharedUsers: $shared);
		}
		$suspect = $this->proxies->suspect();
		if ($suspect !== null) {
			$hex = RangeCodec::addressHex($suspect[0]);
			if ($suspect[0]->family === $range['family'] && strcmp($range['start'], $hex) <= 0 && strcmp($hex, $range['end']) <= 0) {
				return new BanResult(BanResult::SKIPPED_PROXY, sharedUsers: $suspect[1]);
			}
		}
		return $this->hasTrustedLogin('net_key', $netKeys, $now) ? new BanResult(BanResult::SKIPPED_TRUSTED) : null;
	}

	/**
	 * The number of people, if it reaches the safety valve's threshold; 0 otherwise.
	 */
	private function sharedUsers(int $users): int {
		$threshold = $this->settings->getInt(GlobalSettings::BAN_SHARED_IP_USERS);
		return $threshold > 0 && $users >= $threshold ? $users : 0;
	}

	/**
	 * @param 'ip'|'net_key' $column
	 */
	private function hasTrustedLogin(string $column, KeyMatch $keys, int $now): bool {
		$uids = [];
		foreach ($this->history->acceptedFrom($column, $keys, $now - self::TRUSTED_LOGIN_DAYS * 86400, self::TRUSTED_LOGIN_ROWS) as $login) {
			if ($login['confirmed']) {
				return true;
			}
			$uids[$login['uid']] = true;
		}
		foreach (array_keys($uids) as $uid) {
			if ($this->groups->isAdmin((string)$uid)) {
				return true;
			}
		}
		return false;
	}
}
