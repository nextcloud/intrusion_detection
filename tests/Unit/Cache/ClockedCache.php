<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Cache;

use OC\Memcache\ArrayCache;

/**
 * An in-memory cache whose entries expire by the test's clock. Like Redis,
 * a write without a time to live keeps the one the entry has.
 */
final class ClockedCache extends ArrayCache {
	/** @var array<string, int> expiry by key */
	private array $expires = [];

	/**
	 * @param \Closure(): int $now
	 */
	public function __construct(
		private readonly \Closure $now,
	) {
		parent::__construct('');
	}

	#[\Override]
	public function set($key, $value, $ttl = 0) {
		if ($ttl > 0) {
			$this->expires[$key] = ($this->now)() + $ttl;
		} elseif (!$this->hasKey($key)) {
			unset($this->expires[$key]);
		}
		return parent::set($key, $value, $ttl);
	}

	#[\Override]
	public function hasKey($key) {
		if (isset($this->expires[$key]) && $this->expires[$key] <= ($this->now)()) {
			$this->remove($key);
		}
		return parent::hasKey($key);
	}

	#[\Override]
	public function remove($key) {
		unset($this->expires[$key]);
		return parent::remove($key);
	}

	/**
	 * How many entries are held, expired ones included.
	 */
	public function size(): int {
		return count($this->cachedData);
	}
}
