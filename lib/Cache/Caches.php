<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Cache;

use OCA\IntrusionDetection\AppInfo\Application;
use OCP\ICacheFactory;
use OCP\IConfig;
use OCP\IMemcache;

/**
 * The memory caches of the app, one namespace per consumer:
 *
 * - {@see shared()}: the distributed cache when one is configured
 *   ({@see isDistributed()}), else the cache of this web server, else none;
 * - {@see local()}: the cache of this web server, or none.
 *
 * Every cache core hands out offers the atomic add() and inc(). A namespace
 * is created once per process, so every service of a request sees the same
 * cache.
 */
class Caches {
	/** Cache classes that keep their values on one web server only */
	private const LOCAL_ONLY = ['OC\\Memcache\\APCu', 'OC\\Memcache\\ArrayCache'];

	/** @var array<string, ?IMemcache> by kind and namespace */
	private array $caches = [];

	public function __construct(
		private readonly ICacheFactory $factory,
		private readonly IConfig $config,
	) {
	}

	/**
	 * Whether any memory cache is configured.
	 */
	public function isAvailable(): bool {
		return $this->factory->isAvailable() || $this->factory->isLocalCacheAvailable();
	}

	/**
	 * Whether a cache shared by all web servers is configured. Core hands
	 * out the local cache as the distributed one when `memcache.distributed`
	 * is not set, so the factory alone cannot tell.
	 */
	public function isDistributed(): bool {
		$class = ltrim($this->config->getSystemValueString('memcache.distributed', ''), '\\');
		return $class !== '' && !in_array($class, self::LOCAL_ONLY, true) && $this->factory->isAvailable();
	}

	/**
	 * @return 'distributed'|'local'|'none'
	 */
	public function kind(): string {
		return $this->isDistributed() ? 'distributed' : ($this->isAvailable() ? 'local' : 'none');
	}

	public function shared(string $namespace): ?IMemcache {
		$key = 'shared/' . $namespace;
		if (!array_key_exists($key, $this->caches)) {
			$this->caches[$key] = match (true) {
				$this->factory->isLocalCacheAvailable() && !$this->isDistributed() => self::memcache($this->factory->createLocal(self::prefix($namespace))),
				$this->factory->isAvailable() => self::memcache($this->factory->createDistributed(self::prefix($namespace))),
				default => null,
			};
		}
		return $this->caches[$key];
	}

	public function local(string $namespace): ?IMemcache {
		$key = 'local/' . $namespace;
		if (!array_key_exists($key, $this->caches)) {
			$this->caches[$key] = $this->factory->isLocalCacheAvailable() ? self::memcache($this->factory->createLocal(self::prefix($namespace))) : null;
		}
		return $this->caches[$key];
	}

	/**
	 * Empty every cache handed out so far.
	 */
	public function clear(): void {
		foreach ($this->caches as $cache) {
			$cache?->clear();
		}
	}

	private static function prefix(string $namespace): string {
		return Application::APP_ID . '-' . $namespace;
	}

	private static function memcache(mixed $cache): ?IMemcache {
		return $cache instanceof IMemcache ? $cache : null;
	}
}
