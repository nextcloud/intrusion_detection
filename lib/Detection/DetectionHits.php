<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Cache\CountBuffer;
use OCA\IntrusionDetection\Db\DetectionMapper;

/**
 * Hits of a stored detection counted in the memory cache ({@see CountBuffer})
 * instead of in its row: those while its check cools down ({@see Cooldown}),
 * and merged hits that bring no new facts and no higher severity while the
 * row was written less than REFRESH seconds ago, so that the last seen
 * time, which decides what is merged, stays that close.
 *
 * The next merge that writes the row adds them ({@see take()}); the flush
 * adds the rest with their last seen time. Each hit is added once.
 */
class DetectionHits {
	/** The name of the counts in {@see CountBuffer} */
	public const BUFFER = 'hits';
	/**
	 * How far the stored last seen time of a detection may fall behind:
	 * never longer than a cool-down, so that the full evaluation after a
	 * cool-down writes the row and adds the hits counted meanwhile.
	 */
	public const REFRESH = Cooldown::PERIOD;

	public function __construct(
		private readonly DetectionMapper $mapper,
		private readonly CountBuffer $buffer,
	) {
	}

	/**
	 * Count one hit of a stored detection.
	 *
	 * @return bool false when there is no memory cache: then the caller adds the hit to the row
	 */
	public function count(string $detectionId): bool {
		return $this->buffer->count(self::BUFFER, $detectionId);
	}

	/**
	 * Take the hits of a detection that wait in the cache, for the caller
	 * to add with its own write.
	 *
	 * @return array{0: int, 1: int} how many, and when the last was seen
	 */
	public function take(string $detectionId): array {
		return $this->buffer->take(self::BUFFER, $detectionId);
	}

	/**
	 * Write the hits that wait in the memory cache.
	 *
	 * @return bool false when some were left for a later flush
	 */
	public function writeCounts(): bool {
		return $this->buffer->drain(self::BUFFER, function (string $id, array $pending): void {
			$this->mapper->addHits($id, $pending['count'], $pending['last']);
		});
	}
}
