<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Address;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\State\AppState;
use OCP\IMemcache;

/**
 * Caches one verdict per address (per /64 for IPv6, which is what a block
 * covers), under a version that changes whenever every verdict must go:
 * a network block, a blocklist change. A block or lift of one address only
 * replaces the verdict of that address.
 *
 * - With a distributed cache, the version is a random token there. Changing
 *   it writes a new token, so two changes at once can never end on an old
 *   version. A block of one address replaces its verdict for every server;
 *   a request that resolved the old verdict at the same moment cannot
 *   overwrite it, because requests only add missing verdicts. 2 cache gets
 *   per request, the version only once per request.
 * - With only a local cache (APCu), every web server has its own cache: a
 *   change sets a new random version in the database (ids_state, not the
 *   app config, whose every write drops core's cached app config), and each
 *   web server reads it again after at most VERSION_TTL seconds, so a block
 *   reaches every web server within that time. Single-address changes do
 *   the same; the ban service makes one change of many blocks in a request.
 * - Without any memory cache, nothing is cached and every request resolves.
 *
 * A verdict that holds for one IPv6 address but not for the rest of its /64
 * (a blocklist entry smaller than the /64) is kept per address: the /64
 * entry then only names a token under which the addresses of the /64 are
 * cached, and dropping the /64 entry drops them all.
 */
class AddressCache {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'address';
	public const VERSION_TTL = 30;
	public const OK_TTL = 300;
	/** The ids_state row of the version, without a distributed cache */
	public const VERSION_STATE = 'verdict_version';
	private const VERSION_KEY = 'addr:v';

	private ?IMemcache $cache = null;
	private bool $distributed = false;
	private bool $initialised = false;
	private ?string $version = null;
	/** @var array<string, string> per-address tokens of /64s seen in this request */
	private array $splits = [];

	public function __construct(
		private readonly Caches $caches,
		private readonly AppState $state,
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
		$entry = $this->cache->get($this->key($source));
		if (is_array($entry) && is_string($entry['s'] ?? null)) {
			$this->splits[$source->ipKey] = $entry['s'];
			return Verdict::fromArray($this->cache->get($this->addressKey($source, $entry['s'])));
		}
		return Verdict::fromArray($entry);
	}

	/**
	 * Cache a verdict resolved for a request. A verdict another request
	 * stored meanwhile (a block that just happened) is never overwritten.
	 */
	public function set(SourceKey $source, Verdict $verdict, int $now): void {
		$this->store($source, $verdict, $now, false);
	}

	/**
	 * Replace the cached verdict of one address (an IPv6 /64) after its block
	 * changed, on every web server. Without a distributed cache every
	 * verdict is dropped instead, because each web server has its own.
	 */
	public function refresh(SourceKey $source, Verdict $verdict, int $now): void {
		$this->init();
		if (!$this->distributed) {
			$this->bump();
			return;
		}
		$this->store($source, $verdict, $now, true);
	}

	/**
	 * Drop every cached verdict, on every web server.
	 */
	public function bump(): void {
		$this->init();
		$this->version = $this->newVersion();
		$this->splits = [];
		if ($this->distributed) {
			$this->cache?->set(self::VERSION_KEY, $this->version);
			return;
		}
		$this->state->set(self::VERSION_STATE, $this->version);
		$this->cache?->set(self::VERSION_KEY, $this->version, self::VERSION_TTL);
	}

	private function store(SourceKey $source, Verdict $verdict, int $now, bool $replace): void {
		$this->init();
		if ($this->cache === null) {
			return;
		}
		$ttl = max(1, $verdict->cacheUntil - $now);
		if ($source->family === 6 && $verdict->perAddress) {
			if ($replace) {
				// Drops the verdicts of every address of the /64 at once.
				$this->cache->remove($this->key($source));
				unset($this->splits[$source->ipKey]);
				return;
			}
			$split = $this->splits[$source->ipKey] ??= bin2hex(random_bytes(6));
			$this->cache->set($this->key($source), ['s' => $split], self::OK_TTL);
			$this->cache->set($this->addressKey($source, $split), $verdict->toArray(), $ttl);
			return;
		}
		if (!$replace) {
			$this->cache->add($this->key($source), $verdict->toArray(), $ttl);
			return;
		}
		$this->cache->set($this->key($source), $verdict->toArray(), $ttl);
	}

	private function key(SourceKey $source): string {
		return 'addr:' . $this->version() . ':' . $source->ipKey;
	}

	private function addressKey(SourceKey $source, string $split): string {
		return 'addr:' . $this->version() . ':' . $split . ':' . $source->ip;
	}

	private function version(): string {
		if ($this->version !== null) {
			return $this->version;
		}
		$cached = $this->cache?->get(self::VERSION_KEY);
		if (is_string($cached) && $cached !== '') {
			return $this->version = $cached;
		}
		if ($this->distributed) {
			// Lost (evicted or flushed): a fresh token, which no old verdict carries.
			$version = $this->newVersion();
			if ($this->cache !== null && !$this->cache->add(self::VERSION_KEY, $version)) {
				$other = $this->cache->get(self::VERSION_KEY);
				$version = is_string($other) && $other !== '' ? $other : $version;
			}
			return $this->version = $version;
		}
		$version = $this->state->get(self::VERSION_STATE) ?? '0';
		$this->cache?->set(self::VERSION_KEY, $version, self::VERSION_TTL);
		return $this->version = $version;
	}

	/**
	 * A version no earlier one had (with overwhelming probability).
	 */
	private function newVersion(): string {
		return (string)random_int(1, PHP_INT_MAX);
	}

	private function init(): void {
		if ($this->initialised) {
			return;
		}
		$this->initialised = true;
		$this->cache = $this->caches->shared(self::CACHE);
		$this->distributed = $this->cache !== null && $this->caches->isDistributed();
	}
}
