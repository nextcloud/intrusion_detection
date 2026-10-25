<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

use OCA\IntrusionDetection\Blocklist\Db\BlocklistStatMapper;
use OCA\IntrusionDetection\Cache\CountBuffer;
use OCA\IntrusionDetection\Net\SourceKey;

/**
 * Counts the matches per list and day ({@see BlocklistStatMapper}) in the
 * memory cache, so that a list that matches a lot of traffic does not
 * rewrite its row of the day on every match; the counts of each minute are
 * written with one read and one write ({@see CountBuffer}).
 */
class BlocklistMatches {
	/** The name of the counts in {@see CountBuffer} */
	public const BUFFER = 'blocklist';

	public function __construct(
		private readonly BlocklistStatMapper $stats,
		private readonly CountBuffer $buffer,
	) {
	}

	/**
	 * Count one match of an address for a list.
	 */
	public function record(string $listId, SourceKey $source, int $now): void {
		if (!$this->buffer->count(self::BUFFER, $listId, $source->ip)) {
			$this->stats->record($listId, gmdate('Y-m-d', $now), $source->ip);
		}
	}

	/**
	 * Write the matches that wait in the memory cache.
	 *
	 * @return bool false when some were left for a later flush
	 */
	public function writeCounts(): bool {
		return $this->buffer->drain(self::BUFFER, function (string $listId, array $pending): void {
			$this->stats->add($listId, gmdate('Y-m-d', $pending['start']), $pending['count'], array_map('strval', array_keys($pending['details'])));
		});
	}
}
