<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\KeyMatch;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Login\EstablishedAccounts;
use OCA\IntrusionDetection\Net\ProtectedRanges;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IGroupManager;

/**
 * Why an address or network must not be blocked automatically, asked only
 * when a block is about to be created (never on the common path):
 *
 * - Safety valve: at least BAN_SHARED_IP_USERS different people, whose
 *   accounts are at least 3 days old or administrators
 *   ({@see EstablishedAccounts}), logged in successfully from the address
 *   (for a network: from the network) within 24 hours. An office network
 *   or a reverse proxy; freshly registered accounts cannot open it.
 * - Unconfigured reverse proxy, while no trusted proxy is configured: a
 *   private address most of the latest logins of different people came
 *   from ({@see ProxySuspect}), or a private address an administrator
 *   logged in from within TRUSTED_LOGIN_DAYS. On a small server behind such
 *   a proxy every visitor, and so every attack, seems to come from it.
 * - Its people: an administrator logged in from it within
 *   TRUSTED_LOGIN_DAYS, or, for a check about one account
 *   (CheckDefinition::$confirmedLoginsExempt),
 *   that account confirmed a login from it (a second factor, an email code,
 *   admin approval or a remembered device). Requests from such an address
 *   that look like an attack are more likely a misconfigured client. A
 *   confirmed login never exempts an address from blocks for attacks on
 *   other accounts: anyone can make an account confirm a login, for example
 *   by registering one. Trap URLs and injection probes are no client's
 *   mistake, so these logins never exempt from them
 *   (CheckDefinition::$trustedLoginsExempt).
 * - For networks also: the network contains loopback, the server's own
 *   address or an address on the brute-force allowlist.
 *
 * Blocks by hand still work. With a memory cache, the facts about an
 * address or network that do not depend on the check are remembered for
 * REMEMBER seconds, so an address that keeps hitting costs few queries.
 */
class BanExemptions {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'exemptions';
	public const TRUSTED_LOGIN_DAYS = 7;
	/** The facts of an address or network are remembered this long */
	public const REMEMBER = 60;
	/** At most this many different accounts are looked at for an address or network */
	private const MAX_ACCOUNTS = 200;

	public function __construct(
		private readonly LoginMapper $logins,
		private readonly LoginHistoryMapper $history,
		private readonly Settings $settings,
		private readonly ProxySuspect $proxies,
		private readonly ProtectedRanges $protected,
		private readonly IGroupManager $groups,
		private readonly Caches $caches,
		private readonly EstablishedAccounts $accounts,
		private readonly CheckRegistry $registry,
	) {
	}

	/**
	 * Why one address (an IPv4 address, an IPv6 /64) must not be blocked
	 * now, or null when it may be.
	 *
	 * @param string $checkId the check that wants to block it
	 * @param ?string $uid the account the detection is about, if any
	 */
	public function forAddress(SourceKey $source, int $now, string $checkId, ?string $uid = null): ?BanResult {
		[$column, $keys] = $source->family === 4 ? ['ip', new KeyMatch([$source->ip])] : ['net_key', new KeyMatch([$source->ipKey])];
		$facts = $this->remembered('a:' . $source->ipKey, fn (): array => [
			'shared' => $this->sharedUsers($this->logins->distinctUidsForIp($source->ipKey, intdiv($now - 86400, 3600), self::MAX_ACCOUNTS), $now),
			'proxy' => $this->proxies->accountsBehind($source),
		] + $this->accounts($column, $keys, $now, ProxySuspect::isPrivate($source)));
		return $this->decide($facts, $checkId, $uid, $column, $keys, $now);
	}

	/**
	 * Why a network must not be blocked now, or null when it may be.
	 *
	 * @param string $cidr the network
	 * @param KeyMatch $netKeys its keys as the login tables store them: the /24, or the /64s inside an IPv6 network
	 * @param string $checkId the check that wants to block it
	 * @param ?string $uid the account the detection is about, if any
	 */
	public function forNetwork(string $cidr, KeyMatch $netKeys, int $now, string $checkId, ?string $uid = null): ?BanResult {
		$range = RangeCodec::parse($cidr);
		if ($this->protected->overlaps($range['family'], $range['start'], $range['end'])) {
			return new BanResult(BanResult::SKIPPED_NEVER);
		}
		$facts = $this->remembered('n:' . $cidr, function () use ($cidr, $netKeys, $range, $now): array {
			$proxy = 0;
			$suspect = $this->proxies->suspect();
			if ($suspect !== null) {
				$hex = RangeCodec::addressHex($suspect[0]);
				if ($suspect[0]->family === $range['family'] && strcmp($range['start'], $hex) <= 0 && strcmp($hex, $range['end']) <= 0) {
					$proxy = $suspect[1];
				}
			}
			$first = SourceKey::tryFromIp(explode('/', $cidr, 2)[0]);
			return [
				'shared' => $this->sharedUsers($this->logins->distinctUidsForNets($netKeys, intdiv($now - 86400, 3600), self::MAX_ACCOUNTS), $now),
				'proxy' => $proxy,
			] + $this->accounts('net_key', $netKeys, $now, $first !== null && ProxySuspect::isPrivate($first));
		});
		return $this->decide($facts, $checkId, $uid, 'net_key', $netKeys, $now);
	}

	/**
	 * Whether a block of this address that was held back should be reported
	 * now: once per REMEMBER seconds with a memory cache, else every time.
	 */
	public function firstReport(SourceKey $source): bool {
		$cache = $this->caches->local(self::CACHE);
		return $cache === null || $cache->add('ex:r:' . $source->ipKey, 1, self::REMEMBER);
	}

	/**
	 * @param array{shared: int, proxy: int, admin: bool, private: bool, users: int} $facts
	 * @param 'ip'|'net_key' $column
	 */
	private function decide(array $facts, string $checkId, ?string $uid, string $column, KeyMatch $keys, int $now): ?BanResult {
		if ($facts['shared'] > 0) {
			return new BanResult(BanResult::SKIPPED_SHARED, sharedUsers: $facts['shared']);
		}
		// Read live: an administrator who just configured the trusted proxies must not wait for the facts to be forgotten.
		$unconfigured = $this->proxies->unconfigured();
		if ($facts['proxy'] > 0 && $unconfigured) {
			return new BanResult(BanResult::SKIPPED_PROXY, sharedUsers: $facts['proxy']);
		}
		if ($facts['admin'] && $facts['private'] && $unconfigured) {
			return new BanResult(BanResult::SKIPPED_PROXY, sharedUsers: $facts['users']);
		}
		$check = $this->registry->find($checkId);
		if ($check !== null && !$check->trustedLoginsExempt) {
			return null;
		}
		if ($facts['admin']) {
			return new BanResult(BanResult::SKIPPED_TRUSTED);
		}
		if ($uid !== null && $check !== null && $check->confirmedLoginsExempt
			&& $this->history->hasConfirmedLogin($uid, $column, $keys, $now - self::TRUSTED_LOGIN_DAYS * 86400)) {
			return new BanResult(BanResult::SKIPPED_TRUSTED);
		}
		return null;
	}

	/**
	 * Whether an administrator logged in from the address or network within
	 * TRUSTED_LOGIN_DAYS, and how many accounts did. Every account is looked
	 * at, however often the others logged in.
	 *
	 * @param 'ip'|'net_key' $column
	 * @return array{admin: bool, private: bool, users: int}
	 */
	private function accounts(string $column, KeyMatch $keys, int $now, bool $private): array {
		$uids = $this->history->acceptedUidsFrom($column, $keys, $now - self::TRUSTED_LOGIN_DAYS * 86400, self::MAX_ACCOUNTS);
		$admin = false;
		foreach ($uids as $uid) {
			if ($this->groups->isAdmin($uid)) {
				$admin = true;
				break;
			}
		}
		return ['admin' => $admin, 'private' => $private, 'users' => count($uids)];
	}

	/**
	 * The number of people, if it reaches the safety valve's threshold; 0
	 * otherwise. Only established accounts count ({@see EstablishedAccounts}).
	 *
	 * @param list<string> $uids
	 */
	private function sharedUsers(array $uids, int $now): int {
		$threshold = $this->settings->getInt(GlobalSettings::BAN_SHARED_IP_USERS);
		if ($threshold <= 0 || count($uids) < $threshold) {
			return 0;
		}
		$users = $this->accounts->count($uids, $now);
		return $users >= $threshold ? $users : 0;
	}

	/**
	 * @param \Closure(): array{shared: int, proxy: int, admin: bool, private: bool, users: int} $load
	 * @return array{shared: int, proxy: int, admin: bool, private: bool, users: int}
	 */
	private function remembered(string $key, \Closure $load): array {
		$cache = $this->caches->local(self::CACHE);
		$cached = $cache?->get('ex:' . $key);
		if (is_array($cached) && is_int($cached['shared'] ?? null) && is_int($cached['proxy'] ?? null) && is_bool($cached['admin'] ?? null)
			&& is_bool($cached['private'] ?? null) && is_int($cached['users'] ?? null)) {
			return ['shared' => $cached['shared'], 'proxy' => $cached['proxy'], 'admin' => $cached['admin'], 'private' => $cached['private'], 'users' => $cached['users']];
		}
		$facts = $load();
		$cache?->set('ex:' . $key, $facts, self::REMEMBER);
		return $facts;
	}
}
