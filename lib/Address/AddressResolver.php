<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Address;

use OCA\IntrusionDetection\Blocklist\BlocklistFactsProvider;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Net\Ipv6Networks;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\AppFramework\Utility\ITimeFactory;
use Psr\Container\ContainerInterface;

/**
 * Resolves the verdict for an address from the database: one indexed query
 * on the bans (the address and the networks around it), plus whatever the fact
 * providers add. Used on a cold cache only.
 */
class AddressResolver {
	/** @var list<class-string<IAddressFactsProvider>> */
	public const PROVIDERS = [
		BlocklistFactsProvider::class,
	];

	public function __construct(
		private readonly BanMapper $banMapper,
		private readonly ITimeFactory $timeFactory,
		private readonly ContainerInterface $container,
	) {
	}

	public function resolve(SourceKey $source): Verdict {
		$now = $this->timeFactory->getTime();
		$denyUntil = 0;
		$reference = '';
		foreach ($this->banMapper->findActiveForKeys(self::banKeys($source), $now) as $ban) {
			if ($ban->getExpiresAt() > $denyUntil) {
				$denyUntil = $ban->getExpiresAt();
				$reference = $ban->getDisplayReference();
			}
		}

		$attributes = [];
		foreach (self::PROVIDERS as $class) {
			/** @var IAddressFactsProvider $provider */
			$provider = $this->container->get($class);
			$facts = $provider->facts($source);
			if ($facts->denyUntil > $denyUntil) {
				$denyUntil = $facts->denyUntil;
				$reference = $facts->reference;
			}
			array_push($attributes, ...$facts->attributes);
		}

		$cacheUntil = $denyUntil > $now ? $denyUntil : $now + AddressCache::OK_TTL;
		return new Verdict($denyUntil, $reference, array_values(array_unique($attributes)), $cacheUntil);
	}

	/**
	 * The active bans that block an address now, for the admin page lookup.
	 *
	 * @return list<Ban>
	 */
	public function activeBans(SourceKey $source): array {
		return $this->banMapper->findActiveForKeys(self::banKeys($source), $this->timeFactory->getTime());
	}

	/**
	 * The ban keys that block an address: the address and its /24 for IPv4;
	 * its /64, /56 and /48 for IPv6.
	 *
	 * @return list<string>
	 */
	public static function banKeys(SourceKey $source): array {
		if ($source->family === 4) {
			return [$source->ipKey, $source->netKey];
		}
		$keys = [$source->ipKey];
		foreach (Ipv6Networks::PREFIXES as $prefix) {
			$keys[] = Ipv6Networks::key($source, $prefix);
		}
		return $keys;
	}
}
