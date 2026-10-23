<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Login;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCP\IUser;
use OCP\IUserManager;

/**
 * The accounts with an email address, for failed logins and reset requests
 * that use one. Core's lookup cannot use an index (and asks every user
 * backend, e.g. LDAP), and an attack on an account repeats its address, so
 * an address that has accounts is kept for TTL seconds in the memory cache.
 * An address without one is not kept: lists of made-up addresses rarely
 * repeat one, and would only fill the cache. The cache key is a hash of the
 * address; the value holds only uids.
 */
class EmailAccounts {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'email-accounts';
	public const TTL = 60;

	public function __construct(
		private readonly IUserManager $userManager,
		private readonly Caches $caches,
		private readonly Fingerprinter $fingerprinter,
	) {
	}

	/**
	 * The uid of the only account with this address, null when none or several have it.
	 */
	public function only(string $email, bool $enabledOnly = false): ?string {
		$accounts = array_filter($this->accounts($email), static fn (array $a): bool => !$enabledOnly || $a['enabled']);
		return count($accounts) === 1 ? reset($accounts)['uid'] : null;
	}

	/**
	 * @return list<array{uid: string, enabled: bool}>
	 */
	private function accounts(string $email): array {
		$key = 'email:' . $this->fingerprinter->lookup(mb_strtolower(trim($email)));
		$cached = $this->caches->shared(self::CACHE)?->get($key);
		if (is_array($cached)) {
			$accounts = [];
			foreach ($cached as $account) {
				if (is_array($account) && is_string($account['uid'] ?? null) && is_bool($account['enabled'] ?? null)) {
					$accounts[] = ['uid' => $account['uid'], 'enabled' => $account['enabled']];
				}
			}
			return $accounts;
		}
		$accounts = array_values(array_map(static fn (IUser $u): array => ['uid' => $u->getUID(), 'enabled' => $u->isEnabled()], $this->userManager->getByEmail($email)));
		if ($accounts !== []) {
			$this->caches->shared(self::CACHE)?->set($key, $accounts, self::TTL);
		}
		return $accounts;
	}
}
