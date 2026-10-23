<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\RiskyNetwork;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactsMerger;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a risky network detection recorded: why the address of a password
 * login is risky.
 */
final readonly class RiskyNetworkFacts implements IMergeableFacts {
	/**
	 * @param list<string> $attributes what the address is, such as 'tor' or 'hosting'
	 * @param list<string> $lists the ids of the lists it is on
	 * @param list<string> $listNames their names when it was detected
	 * @param bool $client an app or script logged in, not the login page
	 */
	public function __construct(
		public array $attributes = [],
		public array $lists = [],
		public array $listNames = [],
		public bool $client = false,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::strings($stored, 'attributes') ?? [],
			FactValues::strings($stored, 'lists') ?? [],
			FactValues::strings($stored, 'listNames') ?? [],
			FactValues::bool($stored, 'client') ?? false,
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'attributes' => $this->attributes,
			'lists' => $this->lists,
			'listNames' => $this->listNames,
			'client' => $this->client,
		] + $this->common->toArray();
	}

	/**
	 * What the address is of every hit; the rest is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			FactsMerger::union($old->attributes, $new->attributes) ?? [],
			FactsMerger::union($old->lists, $new->lists) ?? [],
			FactsMerger::union($old->listNames, $new->listNames) ?? [],
			$new->client,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
