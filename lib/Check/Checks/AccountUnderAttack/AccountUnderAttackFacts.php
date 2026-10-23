<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\AccountUnderAttack;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What an account under attack detection recorded: the failed logins for
 * one account from many addresses.
 */
final readonly class AccountUnderAttackFacts implements IMergeableFacts {
	/**
	 * @param int $failures the failed logins for the account within the window
	 * @param int $sources the addresses they came from
	 * @param string $lastSource the address of the most recent one
	 */
	public function __construct(
		public int $failures = 0,
		public int $sources = 0,
		public string $lastSource = '',
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::int($stored, 'failures') ?? 0,
			FactValues::int($stored, 'sources') ?? 0,
			FactValues::string($stored, 'lastSource') ?? '',
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'failures' => $this->failures,
			'sources' => $this->sources,
			'lastSource' => $this->lastSource,
		] + $this->common->toArray();
	}

	/**
	 * The counts and the address are the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$new->failures,
			$new->sources,
			$new->lastSource,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
