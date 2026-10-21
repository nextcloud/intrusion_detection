<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\CredentialUse;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\ICache;
use OCP\ICacheFactory;

/**
 * Keeps each credential's {@see CredentialHistory} in the memory cache,
 * under `cu:<cred_key>`. The key is a keyed fingerprint of the credential
 * and is never written to the database.
 *
 * - With a distributed cache, every web server sees every use.
 * - With only a local cache (APCu), each web server sees its own requests.
 * - Without a memory cache nothing is tracked: tracking in the database
 *   would cost a write per request, so the check is unavailable.
 *
 * The common case costs one cache get and no write.
 */
class CredentialTracker {
	public const KEY_PREFIX = 'cu:';
	/** Entries outlive the longest window by one refresh interval */
	public const TTL = 3600 + CredentialHistory::REFRESH;

	private ?ICache $cache = null;
	private bool $initialised = false;

	public function __construct(
		private readonly ICacheFactory $cacheFactory,
		private readonly Settings $settings,
	) {
	}

	/**
	 * The same tracker on another cache, for measurements that must not
	 * touch the real entries.
	 */
	public function withCache(ICache $cache): self {
		$clone = clone $this;
		$clone->cache = $cache;
		$clone->initialised = true;
		return $clone;
	}

	public function isAvailable(): bool {
		$this->init();
		return $this->cache !== null;
	}

	/**
	 * Note one use of a credential from an address.
	 *
	 * Before authentication, credentials without an entry are not written
	 * (`$create` false): only a credential that logged in once gets one, so
	 * made-up credentials cannot fill the cache.
	 *
	 * @param string $credKey {@see \OCA\IntrusionDetection\Crypto\Fingerprinter::credential()}
	 * @param ?\Closure(): bool $skip asked only when something would be written; true leaves the entry untouched
	 * @param bool $create whether a credential without an entry gets one
	 * @param-out bool $unknown whether the credential had no entry and none was created
	 * @return ?CredentialSwitch the switch when the check fires
	 */
	public function track(#[\SensitiveParameter] string $credKey, SourceKey $source, string $userTag, int $now, ?\Closure $skip = null, bool $create = true, ?bool &$unknown = null): ?CredentialSwitch {
		$unknown = false;
		$this->init();
		if ($this->cache === null) {
			return null;
		}
		$key = self::KEY_PREFIX . $credKey;
		$history = CredentialHistory::fromCache($this->cache->get($key));
		if ($history->isCurrent($source, $now)) {
			return null;
		}
		if (!$create && $history->isEmpty()) {
			$unknown = true;
			return null;
		}
		if ($skip !== null && $skip()) {
			return null;
		}
		$switch = $history->record($source, $userTag, $now, fn (): array => [
			$this->settings->paramInt(TokenConcurrentUse::ID, TokenConcurrentUse::PARAM_WINDOW),
			$this->settings->paramInt(TokenConcurrentUse::ID, TokenConcurrentUse::PARAM_MIN_SWITCHES),
		]);
		$this->cache->set($key, $history->toCache(), self::TTL);
		return $switch;
	}

	private function init(): void {
		if ($this->initialised) {
			return;
		}
		$this->initialised = true;
		// Without a distributed cache configured, core hands out the local one.
		if ($this->cacheFactory->isAvailable()) {
			$this->cache = $this->cacheFactory->createDistributed(Application::APP_ID);
		} elseif ($this->cacheFactory->isLocalCacheAvailable()) {
			$this->cache = $this->cacheFactory->createLocal(Application::APP_ID);
		}
	}
}
