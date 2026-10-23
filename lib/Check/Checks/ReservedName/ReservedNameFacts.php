<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\ReservedName;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a reserved name detection recorded: the reserved name an address
 * tried to log in as.
 */
final readonly class ReservedNameFacts implements IMergeableFacts {
	/**
	 * @param string $name the reserved name, which no account uses
	 */
	public function __construct(
		public string $name = '',
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::string($stored, 'name') ?? '',
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'name' => $this->name,
		] + $this->common->toArray();
	}

	/**
	 * The name is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$new->name,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
