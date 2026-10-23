<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\DirectoryScraping;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a directory scraping detection recorded: the requests of one kind
 * an account made within the counting window.
 */
final readonly class DirectoryScrapingFacts implements IMergeableFacts {
	/**
	 * @param string $group the kind of request, one of the DirectoryRoutes groups
	 * @param int $count the requests within the window
	 * @param int $limit the limit of the group at that time
	 * @param int $window the counting window in seconds
	 * @param int $until when the rate limit of the group ends
	 */
	public function __construct(
		public string $group = '',
		public int $count = 0,
		public int $limit = 0,
		public int $window = DirectoryScraping::WINDOW,
		public int $until = 0,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::string($stored, 'group') ?? '',
			FactValues::int($stored, 'count') ?? 0,
			FactValues::int($stored, 'limit') ?? 0,
			FactValues::int($stored, 'window') ?? DirectoryScraping::WINDOW,
			FactValues::int($stored, 'until') ?? 0,
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'group' => $this->group,
			'count' => $this->count,
			'limit' => $this->limit,
			'window' => $this->window,
			'until' => $this->until,
		] + $this->common->toArray();
	}

	/**
	 * Everything is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$new->group,
			$new->count,
			$new->limit,
			$new->window,
			$new->until,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
