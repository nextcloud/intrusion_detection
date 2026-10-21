<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Login;

use OCA\IntrusionDetection\AppInfo\Application;
use OCP\Config\IUserConfig;
use OCP\Config\ValueType;
use OCP\ICache;
use OCP\ICacheFactory;
use OCP\IGroupManager;

/**
 * Which accounts count as people of this server for "many people use this
 * address" (the safety valve, an unconfigured reverse proxy): those whose
 * first login is at least MIN_AGE ago, and administrators. Anyone who can
 * register accounts could otherwise create a handful and log in with them
 * from the address they attack from, so that it is never blocked.
 *
 * The first login is the one core records ({@see \OCP\IUser::getFirstLogin()}),
 * read for all accounts of an address with one query. An account that never
 * logged in, or no longer exists, counts as new. One whose first login core
 * does not know (it was before Nextcloud 31, which started recording it) is
 * old by definition. The first login of each account is remembered in the
 * memory cache for CACHE_TTL; administrators are only asked about for new
 * accounts.
 */
class EstablishedAccounts {
	/** Accounts count once their first login is this long ago */
	public const MIN_AGE = 3 * 86400;
	public const CACHE_TTL = 3600;

	private ?ICache $cache = null;
	private bool $cacheInitialised = false;

	public function __construct(
		private readonly IUserConfig $userConfig,
		private readonly IGroupManager $groups,
		private readonly ICacheFactory $cacheFactory,
	) {
	}

	/**
	 * How many of the accounts count.
	 *
	 * @param list<string> $uids
	 */
	public function count(array $uids, int $now): int {
		$firstLogins = $this->firstLogins($uids);
		$count = 0;
		foreach ($uids as $uid) {
			if ($this->isEstablished($uid, $firstLogins[$uid] ?? 0, $now)) {
				$count++;
			}
		}
		return $count;
	}

	public function counts(string $uid, int $now): bool {
		return $this->isEstablished($uid, $this->firstLogins([$uid])[$uid] ?? 0, $now);
	}

	private function isEstablished(string $uid, int $firstLogin, int $now): bool {
		return $firstLogin === -1 || ($firstLogin > 0 && $firstLogin <= $now - self::MIN_AGE) || $this->groups->isAdmin($uid);
	}

	/**
	 * The first logins as core records them: a time, 0 for never (or no such
	 * account), -1 for before Nextcloud 31.
	 *
	 * @param list<string> $uids
	 * @return array<string, int>
	 */
	private function firstLogins(array $uids): array {
		$cache = $this->cache();
		$found = [];
		$missing = [];
		foreach ($uids as $uid) {
			$cached = $cache?->get('first-login:' . $uid);
			if (is_int($cached)) {
				$found[$uid] = $cached;
			} else {
				$missing[] = $uid;
			}
		}
		if ($missing === []) {
			return $found;
		}
		$stored = $this->userConfig->getValuesByUsers('login', 'firstLogin', ValueType::INT, $missing);
		foreach ($missing as $uid) {
			$value = $stored[$uid] ?? 0;
			$found[$uid] = is_int($value) ? $value : (int)$value;
			$cache?->set('first-login:' . $uid, $found[$uid], self::CACHE_TTL);
		}
		return $found;
	}

	private function cache(): ?ICache {
		if (!$this->cacheInitialised) {
			$this->cacheInitialised = true;
			$this->cache = $this->cacheFactory->isLocalCacheAvailable() ? $this->cacheFactory->createLocal(Application::APP_ID) : null;
		}
		return $this->cache;
	}
}
