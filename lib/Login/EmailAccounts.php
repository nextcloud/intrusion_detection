<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Login;

use OCA\IntrusionDetection\AppInfo\Application;
use OCP\ICache;
use OCP\ICacheFactory;
use OCP\IUser;
use OCP\IUserManager;

/**
 * The accounts with an email address, for failed logins and reset requests
 * that use one. Core's lookup cannot use an index (and asks every user
 * backend, e.g. LDAP), and an attack repeats the same addresses, so the
 * answer is kept for TTL seconds in the memory cache. The cache key is a
 * hash of the address; the value holds only uids.
 */
class EmailAccounts {
	public const TTL = 60;

	private ?ICache $cache = null;
	private bool $cacheInitialised = false;

	public function __construct(
		private readonly IUserManager $userManager,
		private readonly ICacheFactory $cacheFactory,
	) {
	}

	/**
	 * Whether lookups are cached, so that repeating one is cheap.
	 */
	public function isCached(): bool {
		return $this->cache() !== null;
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
		$key = 'email:' . hash('sha256', mb_strtolower(trim($email)));
		$cached = $this->cache()?->get($key);
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
		$this->cache()?->set($key, $accounts, self::TTL);
		return $accounts;
	}

	private function cache(): ?ICache {
		if (!$this->cacheInitialised) {
			$this->cacheInitialised = true;
			if ($this->cacheFactory->isAvailable()) {
				$this->cache = $this->cacheFactory->createDistributed(Application::APP_ID);
			} elseif ($this->cacheFactory->isLocalCacheAvailable()) {
				$this->cache = $this->cacheFactory->createLocal(Application::APP_ID);
			}
		}
		return $this->cache;
	}
}
