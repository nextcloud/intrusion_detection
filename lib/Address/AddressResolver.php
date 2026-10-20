<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Address;

use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\AppFramework\Utility\ITimeFactory;
use Psr\Container\ContainerInterface;

/**
 * Resolves the verdict for an address from the database: one indexed query
 * on the bans (the address and its network), plus whatever the fact
 * providers add. Used on a cold cache only.
 */
class AddressResolver {
	/** @var list<class-string<IAddressFactsProvider>> */
	public const PROVIDERS = [];

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
		foreach ($this->banMapper->findActiveForKeys(array_values(array_unique([$source->ipKey, $source->netKey])), $now) as $ban) {
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
		return $this->banMapper->findActiveForKeys(array_values(array_unique([$source->ipKey, $source->netKey])), $this->timeFactory->getTime());
	}
}
