<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\StepUpRefused;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactsMerger;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a refused login recorded: why it needed confirmation.
 */
final readonly class StepUpRefusedFacts implements IMergeableFacts {
	/**
	 * @param list<string> $policies why the login needed confirmation ({@see \OCA\IntrusionDetection\Confirm\StepUpPolicy})
	 */
	public function __construct(
		public array $policies = [],
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::strings($stored, 'policies') ?? [],
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'policies' => $this->policies,
		] + $this->common->toArray();
	}

	/**
	 * The reasons of every hit.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			FactsMerger::union($old->policies, $new->policies) ?? [],
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
