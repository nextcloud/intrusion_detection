<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\BlocklistMatch;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactsMerger;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a blocklist match recorded: the blocklists an address that failed
 * to log in is on.
 */
final readonly class BlocklistMatchFacts implements IMergeableFacts {
	/** The address failed to log in */
	public const TRIGGER_FAILED_LOGIN = 'failed_login';

	/**
	 * @param list<string> $lists the ids of the lists
	 * @param list<string> $listNames their names when it was detected
	 * @param string $trigger what the address did, {@see self::TRIGGER_FAILED_LOGIN}
	 */
	public function __construct(
		public array $lists = [],
		public array $listNames = [],
		public string $trigger = '',
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::strings($stored, 'lists') ?? [],
			FactValues::strings($stored, 'listNames') ?? [],
			FactValues::string($stored, 'trigger') ?? '',
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'lists' => $this->lists,
			'listNames' => $this->listNames,
			'trigger' => $this->trigger,
		] + $this->common->toArray();
	}

	/**
	 * The lists of every hit; the trigger is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			FactsMerger::union($old->lists, $new->lists) ?? [],
			FactsMerger::union($old->listNames, $new->listNames) ?? [],
			$new->trigger,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
