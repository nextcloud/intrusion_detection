<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\BlocklistStatMapper;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Read models of the lists for the admin page, occ and the setup check.
 *
 * @psalm-type ListStatus = array{
 *     id: string,
 *     name: string,
 *     url: string,
 *     format: string,
 *     purpose: string,
 *     mode: ?string,
 *     enabled: bool,
 *     builtin: bool,
 *     interval: int,
 *     termsUrl: ?string,
 *     reference: ?string,
 *     ranges: int,
 *     entries: int,
 *     skipped: int,
 *     version: ?int,
 *     lastAttemptAt: ?int,
 *     lastSuccessAt: ?int,
 *     lastFailureAt: ?int,
 *     lastError: ?string,
 *     failures: int,
 *     stale: bool,
 * }
 * @psalm-type DayStats = array{day: string, matches: int, sample: list<string>}
 */
class BlocklistOverview {
	public function __construct(
		private readonly SourceRepository $sources,
		private readonly StateStore $states,
		private readonly BlocklistStatMapper $stats,
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
		private readonly AddressCache $addressCache,
	) {
	}

	/**
	 * Whether matches are counted: only with a memory cache, see {@see BlocklistFactsProvider}.
	 */
	public function countsMatches(): bool {
		return $this->addressCache->isAvailable();
	}

	/**
	 * Every list with its definition and sync status.
	 *
	 * @return list<ListStatus>
	 */
	public function lists(): array {
		$now = $this->timeFactory->getTime();
		$globalInterval = $this->settings->getInt(GlobalSettings::BLOCKLIST_SYNC_INTERVAL);
		$states = $this->states->all();
		$lists = [];
		foreach ($this->sources->all() as $source) {
			$state = $states[$source->id] ?? new ListState();
			$interval = $source->effectiveInterval($globalInterval);
			$lists[] = [
				'id' => $source->id,
				'name' => $source->name,
				'url' => $source->url,
				'format' => $source->format->value,
				'purpose' => $source->purpose,
				'mode' => $source->mode,
				'enabled' => $source->enabled,
				'builtin' => $source->builtin,
				'interval' => $interval,
				'termsUrl' => $source->termsUrl,
				'reference' => $source->isDeny() ? $this->sources->reference($source->id) : null,
				'ranges' => $state->ranges,
				'entries' => $state->entries,
				'skipped' => $state->skipped,
				'version' => $state->version,
				'lastAttemptAt' => $state->attemptAt,
				'lastSuccessAt' => $state->successAt,
				'lastFailureAt' => $state->failureAt,
				'lastError' => $state->error,
				'failures' => $state->failures,
				'stale' => $source->enabled && $state->isStale($interval, $now),
			];
		}
		return $lists;
	}

	/**
	 * Enabled lists that have not synced successfully for more than three intervals.
	 *
	 * @return list<ListStatus>
	 */
	public function stale(): array {
		return array_values(array_filter($this->lists(), static fn (array $l): bool => $l['stale']));
	}

	/**
	 * Matches per day of every list, blocklists and network lists, newest day first.
	 *
	 * @return array<string, list<DayStats>> keyed by list id
	 */
	public function matches(int $days = 14): array {
		$ids = array_keys($this->sources->all());
		$since = gmdate('Y-m-d', $this->timeFactory->getTime() - max(0, $days - 1) * 86400);
		$byList = array_fill_keys($ids, []);
		foreach ($this->stats->findSince($ids, $since) as $row) {
			$byList[$row['listId']][] = ['day' => $row['day'], 'matches' => $row['matches'], 'sample' => $row['sample']];
		}
		return $byList;
	}
}
