<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Address;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IAppConfig;
use OCP\ICache;
use OCP\ICacheFactory;

/**
 * Caches one verdict per address, under a version that is bumped on every
 * change of bans or blocklists, so a change invalidates all verdicts at once.
 *
 * - With a distributed cache, the version lives there: 2 cache gets per request.
 * - With only a local cache (APCu), each web server keeps its own copy of the
 *   version for at most VERSION_TTL seconds and reloads it from app config, so
 *   a block reaches every web server within that time.
 * - Without any memory cache, nothing is cached and every request resolves.
 */
class AddressCache {
	public const VERSION_TTL = 30;
	public const OK_TTL = 300;
	private const VERSION_KEY = 'addr:v';

	private ?ICache $cache = null;
	private bool $distributed = false;
	private bool $initialised = false;

	public function __construct(
		private readonly ICacheFactory $cacheFactory,
		private readonly IAppConfig $appConfig,
	) {
	}

	public function isAvailable(): bool {
		$this->init();
		return $this->cache !== null;
	}

	public function isDistributed(): bool {
		$this->init();
		return $this->distributed;
	}

	public function get(SourceKey $source): ?Verdict {
		$this->init();
		if ($this->cache === null) {
			return null;
		}
		return Verdict::fromArray($this->cache->get($this->key($source)));
	}

	public function set(SourceKey $source, Verdict $verdict, int $now): void {
		$this->init();
		if ($this->cache === null) {
			return;
		}
		$ttl = max(1, $verdict->cacheUntil - $now);
		$this->cache->set($this->key($source), $verdict->toArray(), $ttl);
	}

	/**
	 * Invalidate every cached verdict, on every web server.
	 */
	public function bump(): void {
		$version = $this->appConfig->getValueInt(Application::APP_ID, GlobalSettings::BAN_VERSION) + 1;
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::BAN_VERSION, $version);
		$this->init();
		if ($this->cache !== null) {
			$this->cache->set(self::VERSION_KEY, $version, $this->distributed ? 0 : self::VERSION_TTL);
		}
	}

	private function key(SourceKey $source): string {
		return 'addr:' . $this->version() . ':' . $source->ip;
	}

	private function version(): int {
		$cached = $this->cache?->get(self::VERSION_KEY);
		if (is_int($cached)) {
			return $cached;
		}
		$version = $this->appConfig->getValueInt(Application::APP_ID, GlobalSettings::BAN_VERSION);
		$this->cache?->set(self::VERSION_KEY, $version, $this->distributed ? 0 : self::VERSION_TTL);
		return $version;
	}

	private function init(): void {
		if ($this->initialised) {
			return;
		}
		$this->initialised = true;
		if ($this->cacheFactory->isAvailable()) {
			$this->cache = $this->cacheFactory->createDistributed(Application::APP_ID);
			$this->distributed = true;
		} elseif ($this->cacheFactory->isLocalCacheAvailable()) {
			$this->cache = $this->cacheFactory->createLocal(Application::APP_ID);
		}
	}
}
