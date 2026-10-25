<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Blocklist\BlocklistMatches;
use OCA\IntrusionDetection\Cache\CountBuffer;
use OCA\IntrusionDetection\Db\IPurges;
use OCA\IntrusionDetection\Detection\DetectionHits;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use Psr\Container\ContainerInterface;

/**
 * Writes the counts that wait in the memory cache ({@see CountBuffer}):
 * with the cleanup job, and from a web request with a verdict miss when
 * they are due. The owners are only built when a flush runs.
 */
class PendingCounts implements IPurges {
	/** The owners of counts in the cache, in the order they are written */
	public const OWNERS = [FailedLoginStats::class, BlocklistMatches::class, DetectionHits::class];

	public function __construct(
		private readonly CountBuffer $buffer,
		private readonly ContainerInterface $container,
	) {
	}

	/**
	 * Write every count, unless another flush runs.
	 *
	 * @return int how many members were written
	 */
	#[\Override]
	public function purge(int $now): int {
		$this->buffer->flush($this->writers(), PHP_INT_MAX, $written);
		return $written;
	}

	/**
	 * Write the counts when they are due; see {@see CountBuffer::flushIfDue()}.
	 */
	public function flushIfDue(): void {
		$this->buffer->flushIfDue($this->writers(...));
	}

	/**
	 * @return list<\Closure(): bool> the owners' writers
	 */
	private function writers(): array {
		$writers = [];
		foreach (self::OWNERS as $class) {
			$owner = $this->container->get($class);
			if ($owner instanceof FailedLoginStats || $owner instanceof BlocklistMatches || $owner instanceof DetectionHits) {
				$writers[] = $owner->writeCounts(...);
			}
		}
		return $writers;
	}
}
