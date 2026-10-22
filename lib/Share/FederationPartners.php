<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Share;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\FlagMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Share\Exceptions\ShareNotFound;
use OCP\Share\IManager as IShareManager;
use OCP\Share\IShare;
use Psr\Container\ContainerInterface;

/**
 * Addresses of servers this one shares files with: an address that opened
 * a federated share of this server is remembered until REMEMBER seconds
 * after it last did. Only the receiving server knows the token of a
 * federated share, so a valid one is proof of a partner.
 *
 * A partner server keeps opening federated shares that were deleted here
 * without telling it, for example with their owner's account or after
 * their files left the trash bin. Unknown share links from a partner are
 * reported, but never block it ({@see \OCA\IntrusionDetection\Check\Checks\ShareBruteforce}).
 *
 * The mark is a flag of its own (`fed:` and the address key in ids_flags),
 * which only the share link check reads. With a memory cache, a token is
 * looked up for an address once per CHECK_EVERY seconds, and the mark is
 * written only when it is missing or half expired.
 */
class FederationPartners {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'federation';
	/** Share types whose token only another server knows */
	public const SHARE_TYPES = [IShare::TYPE_REMOTE, IShare::TYPE_REMOTE_GROUP];
	/** An address stays a partner this long after it last opened a federated share */
	public const REMEMBER = FlaggedSources::DURATION;
	/** With a memory cache, a token is looked up for an address once in this many seconds */
	public const CHECK_EVERY = 3600;
	public const REASON = 'federation';

	public function __construct(
		private readonly FlagMapper $flags,
		private readonly Fingerprinter $fingerprinter,
		private readonly ContainerInterface $container,
		private readonly Caches $caches,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * Remember the address if the token, with which a request was just
	 * authenticated, is the token of a federated share.
	 */
	public function observe(SourceKey $source, #[\SensitiveParameter] string $token): void {
		if ($token === '') {
			return;
		}
		$cache = $this->caches->local(self::CACHE);
		if ($cache !== null && !$cache->add('fed:' . $source->ipKey . ':' . $this->fingerprinter->credential($token), 1, self::CHECK_EVERY)) {
			return;
		}
		try {
			$share = $this->container->get(IShareManager::class)->getShareByToken($token);
		} catch (ShareNotFound) {
			return;
		}
		if (!in_array($share->getShareType(), self::SHARE_TYPES, true)) {
			return;
		}
		$now = $this->timeFactory->getTime();
		$this->flags->flag(self::key($source), self::REASON, $now + self::REMEMBER, null, $now);
	}

	public function isPartner(SourceKey $source): bool {
		return $this->among([$source]) !== [];
	}

	/**
	 * The address keys of the partners among the given addresses, in one query.
	 *
	 * @param list<SourceKey> $sources
	 * @return list<string>
	 */
	public function among(array $sources): array {
		if ($sources === []) {
			return [];
		}
		$keys = array_values(array_unique(array_map(static fn (SourceKey $source): string => self::key($source), $sources)));
		$active = $this->flags->active($keys, $this->timeFactory->getTime());
		return array_map(static fn (string $key): string => substr($key, 4), array_keys($active));
	}

	private static function key(SourceKey $source): string {
		return 'fed:' . $source->ipKey;
	}
}
