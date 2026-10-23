<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Cache;

use OCA\IntrusionDetection\Cache\Caches;
use OCP\IMemcache;

/**
 * Caches that hand out the given caches for every namespace: null for none.
 */
final class FixedCaches extends Caches {
	public function __construct(
		private readonly ?IMemcache $sharedCache,
		private readonly ?IMemcache $localCache = null,
		private readonly bool $distributed = false,
	) {
	}

	public static function none(): self {
		return new self(null);
	}

	#[\Override]
	public function isAvailable(): bool {
		return $this->sharedCache !== null || $this->localCache !== null;
	}

	#[\Override]
	public function isDistributed(): bool {
		return $this->distributed;
	}

	#[\Override]
	public function shared(string $namespace): ?IMemcache {
		return $this->sharedCache;
	}

	#[\Override]
	public function local(string $namespace): ?IMemcache {
		return $this->localCache;
	}

	#[\Override]
	public function clear(): void {
		$this->sharedCache?->clear();
		$this->localCache?->clear();
	}
}
