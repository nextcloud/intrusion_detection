<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Address\AddressFacts;
use OCA\IntrusionDetection\Address\IAddressFactsProvider;
use OCA\IntrusionDetection\Blocklist\Db\BlocklistRangeMapper;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch\BlocklistMatch;
use OCA\IntrusionDetection\Check\Checks\RiskyNetwork\RiskyNetwork;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\AppFramework\Utility\ITimeFactory;
use Psr\Log\LoggerInterface;

/**
 * What the downloaded lists say about an address, for its verdict.
 *
 * Runs only when a verdict is resolved (a cold cache), with one indexed
 * query per enabled list that has a synced version (for IPv6 it asks for
 * the whole /64 the verdict is cached for, and only when a list splits the
 * /64 also for the address itself):
 * - a blocklist in Protect (and the check in Protect) refuses the address,
 *   with the list's reference;
 * - a blocklist in Observe, or any blocklist while the check only observes,
 *   adds the attribute `list:<id>`;
 * - a network attribute list adds `hosting` or `tor`, and `net:<id>`.
 *
 * Blocklists are skipped entirely while the blocklist check is off, network
 * attribute lists while neither the hosting and Tor check runs nor the
 * address risk score is on: then nothing reads their attributes.
 *
 * Matches of all lists are counted per list and day ({@see BlocklistMatches}).
 * Counting happens here, on resolve, so it costs nothing on requests with a
 * cached verdict: an address is counted about once per verdict lifetime
 * ({@see AddressCache::OK_TTL}, and again after every block or list change),
 * not once per request. Without a memory cache every request resolves, so
 * nothing is counted then, to avoid a database write per request.
 */
class BlocklistFactsProvider implements IAddressFactsProvider {
	public function __construct(
		private readonly SourceRepository $sources,
		private readonly StateStore $states,
		private readonly BlocklistRangeMapper $ranges,
		private readonly BlocklistMatches $matches,
		private readonly AppSettings $appSettings,
		private readonly CheckSettings $settings,
		private readonly AddressCache $addressCache,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function facts(SourceKey $source): AddressFacts {
		try {
			return $this->lookup($source);
		} catch (\Throwable $e) {
			// A broken list must not take the ban lookup of the same verdict down with it.
			$this->logger->error('Intrusion detection could not look an address up in the blocklists', ['exception' => $e]);
			return new AddressFacts();
		}
	}

	private function lookup(SourceKey $source): AddressFacts {
		$enabled = $this->sources->enabled();
		if ($enabled === []) {
			return new AddressFacts();
		}
		$states = $this->states->all();
		$mode = null;
		$attributesUsed = null;
		$hex = RangeCodec::addressHex($source);
		$slash64 = $source->family === 6 ? RangeCodec::parse($source->ipKey) : null;
		$perAddress = false;
		$now = $this->timeFactory->getTime();
		$denyUntil = 0;
		$reference = '';
		$attributes = [];
		$matched = [];
		foreach ($enabled as $list) {
			$version = ($states[$list->id] ?? null)?->version;
			if ($version === null) {
				continue;
			}
			if ($list->isDeny()) {
				$mode ??= $this->settings->modeState(BlocklistMatch::ID);
				if (!$mode->runs()) {
					continue;
				}
			} else {
				$attributesUsed ??= $this->settings->modeState(RiskyNetwork::ID)->runs() || $this->appSettings->riskEnabled();
				if (!$attributesUsed) {
					continue;
				}
			}
			if ($slash64 !== null) {
				$covered = $this->slash64Match($list->id, $version, $slash64['start'], $slash64['end']);
				if ($covered === null) {
					$perAddress = true;
					$covered = $this->ranges->findContaining($list->id, $version, $source->family, $hex) !== null;
				}
				if (!$covered) {
					continue;
				}
			} elseif ($this->ranges->findContaining($list->id, $version, $source->family, $hex) === null) {
				continue;
			}
			$matched[] = $list->id;
			if (!$list->isDeny()) {
				$attributes[] = $list->attribute();
				$attributes[] = $list->networkAttribute();
				continue;
			}
			if ($list->isProtect() && $mode !== null && $mode->acts()) {
				if ($denyUntil === 0) {
					$denyUntil = $now + AddressCache::OK_TTL;
					$reference = $this->sources->reference($list->id);
				}
			} else {
				$attributes[] = $list->attribute();
			}
		}
		if ($matched !== []) {
			$this->count($matched, $source, $now);
		}
		return new AddressFacts($denyUntil, $reference, array_values(array_unique($attributes)), $perAddress);
	}

	/**
	 * Whether a list covers a whole /64 (true), none of it (false), or only
	 * part of it (null: then the answer depends on the address). One query,
	 * like the lookup of a single address.
	 */
	private function slash64Match(string $listId, int $version, string $first, string $last): ?bool {
		$range = $this->ranges->findLastStartingAtOrBefore($listId, $version, 6, $last);
		if ($range === null || strcmp($range['end'], $first) < 0) {
			return false;
		}
		if (strcmp($range['start'], $first) <= 0 && strcmp($range['end'], $last) >= 0) {
			return true;
		}
		return null;
	}

	/**
	 * @param list<string> $listIds
	 */
	private function count(array $listIds, SourceKey $source, int $now): void {
		if (!$this->addressCache->isAvailable()) {
			return;
		}
		foreach ($listIds as $id) {
			try {
				$this->matches->record($id, $source, $now);
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not count a blocklist match', ['exception' => $e]);
			}
		}
	}
}
