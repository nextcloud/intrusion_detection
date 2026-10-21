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
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\BlocklistRangeMapper;
use OCA\IntrusionDetection\Db\BlocklistStatMapper;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\AppFramework\Utility\ITimeFactory;
use Psr\Log\LoggerInterface;

/**
 * What the downloaded lists say about an address, for its verdict.
 *
 * Runs only when a verdict is resolved (a cold cache), with one indexed
 * query per enabled list that has a synced version:
 * - a blocklist in Protect (and the check in Protect) refuses the address,
 *   with the list's reference;
 * - a blocklist in Observe, or any blocklist while the check only observes,
 *   adds the attribute `list:<id>`;
 * - a network attribute list adds `hosting` or `tor`.
 *
 * Blocklists are skipped entirely while the blocklist check is off.
 *
 * Matches of blocklists are counted per list and day ({@see BlocklistStatMapper}).
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
		private readonly BlocklistStatMapper $stats,
		private readonly Settings $settings,
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
		$hex = RangeCodec::addressHex($source);
		$now = $this->timeFactory->getTime();
		$denyUntil = 0;
		$reference = '';
		$attributes = [];
		$matchedDeny = [];
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
			}
			if ($this->ranges->findContaining($list->id, $version, $source->family, $hex) === null) {
				continue;
			}
			if (!$list->isDeny()) {
				$attributes[] = $list->attribute();
				continue;
			}
			$matchedDeny[] = $list->id;
			if ($list->isProtect() && $mode !== null && $mode->acts()) {
				if ($denyUntil === 0) {
					$denyUntil = $now + AddressCache::OK_TTL;
					$reference = $this->sources->reference($list->id);
				}
			} else {
				$attributes[] = $list->attribute();
			}
		}
		if ($matchedDeny !== []) {
			$this->count($matchedDeny, $source, $now);
		}
		return new AddressFacts($denyUntil, $reference, array_values(array_unique($attributes)));
	}

	/**
	 * @param list<string> $listIds
	 */
	private function count(array $listIds, SourceKey $source, int $now): void {
		if (!$this->addressCache->isAvailable()) {
			return;
		}
		$day = gmdate('Y-m-d', $now);
		foreach ($listIds as $id) {
			try {
				$this->stats->record($id, $day, $source->ip);
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not count a blocklist match', ['exception' => $e]);
			}
		}
	}
}
