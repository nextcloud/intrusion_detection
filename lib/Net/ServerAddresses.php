<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Net;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\State\AppState;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * This server's own addresses, which are never blocked: the one the current
 * web request came in on (`SERVER_ADDR`), and those seen in earlier web
 * requests, for cron and occ, where there is no web request.
 *
 * Each web server adds its own when it resolves a verdict with it
 * ({@see observe()}), as one ids_state row per address with the time it was
 * last seen. A web server writes its row when the address is new or the row
 * is a day old, and then remembers in the memory cache for an hour that it
 * did, so that it reads nothing in between. With each such write, addresses
 * not seen for RETENTION are forgotten, and all but the MAX_REMEMBERED
 * latest.
 */
class ServerAddresses {
	/** The ids_state rows: this prefix and the address, with the time it was last seen */
	public const STATE_PREFIX = 'server_address/';
	/** An address not seen for this long is forgotten */
	public const RETENTION = 30 * 86400;
	/** How often a web server writes the time its address was seen */
	public const REFRESH = 86400;
	/** At most this many addresses are kept, the latest */
	public const MAX_REMEMBERED = 256;
	/** The namespace in {@see Caches} */
	public const CACHE = 'server-address';
	/** How long a web server remembers that its address is stored */
	public const SEEN_TTL = 3600;

	/** @var list<string>|null the remembered addresses, read once per request */
	private ?array $remembered = null;

	public function __construct(
		private readonly AppState $state,
		private readonly Caches $caches,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * Remember the address of this web request's server. Costs one cache
	 * get while the server remembers that it is stored; without a memory
	 * cache, one read by the primary key.
	 */
	public function observe(): void {
		$own = $this->current();
		if ($own === null) {
			return;
		}
		// The server's own address, no personal data.
		$cache = $this->caches->local(self::CACHE) ?? $this->caches->shared(self::CACHE);
		$seen = 'seen/' . $own->ip;
		if ($cache?->get($seen) !== null) {
			return;
		}
		$now = $this->timeFactory->getTime();
		$name = self::STATE_PREFIX . $own->ip;
		if ($this->state->getInt($name) <= $now - self::REFRESH) {
			$this->state->setInt($name, $now);
			$this->forget($now);
		}
		$cache?->set($seen, 1, self::SEEN_TTL);
	}

	public function contains(SourceKey $source): bool {
		foreach ($this->all() as $own) {
			if ($own->ip === $source->ip) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return list<SourceKey> the current one first, then the remembered ones
	 */
	public function all(): array {
		$all = [];
		$current = $this->current();
		if ($current !== null) {
			$all[$current->ip] = $current;
		}
		foreach ($this->remembered() as $ip) {
			$source = SourceKey::tryFromIp($ip);
			if ($source !== null) {
				$all[$source->ip] ??= $source;
			}
		}
		return array_values($all);
	}

	/**
	 * Forget the addresses not seen for RETENTION, and all but the
	 * MAX_REMEMBERED latest.
	 *
	 * @return int how many were forgotten
	 */
	public function forget(int $now): int {
		$forget = [];
		$kept = 0;
		foreach ($this->stored() as $ip => $lastSeen) {
			if ($lastSeen < $now - self::RETENTION || ++$kept > self::MAX_REMEMBERED) {
				$forget[] = self::STATE_PREFIX . $ip;
			}
		}
		$this->remembered = null;
		return $forget === [] ? 0 : $this->state->deleteNames($forget);
	}

	private function current(): ?SourceKey {
		$address = $_SERVER['SERVER_ADDR'] ?? null;
		return is_string($address) ? SourceKey::tryFromIp($address) : null;
	}

	/**
	 * @return list<string> the latest first
	 */
	private function remembered(): array {
		if ($this->remembered === null) {
			$since = $this->timeFactory->getTime() - self::RETENTION;
			$fresh = array_filter($this->stored(), static fn (int $lastSeen): bool => $lastSeen >= $since);
			$this->remembered = array_slice(array_map('strval', array_keys($fresh)), 0, self::MAX_REMEMBERED);
		}
		return $this->remembered;
	}

	/**
	 * @return array<string, int> when each stored address was last seen, the latest first
	 */
	private function stored(): array {
		$stored = array_map('intval', $this->state->getPrefixed(self::STATE_PREFIX));
		arsort($stored);
		return $stored;
	}
}
