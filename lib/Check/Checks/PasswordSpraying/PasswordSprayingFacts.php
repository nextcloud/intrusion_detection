<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\PasswordSpraying;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a password spraying detection recorded. A spray records its counts;
 * an address joining a flagged spray the accounts it tried itself; a login
 * with a flagged password whether an app or script logged in.
 */
final readonly class PasswordSprayingFacts implements IMergeableFacts {
	/**
	 * @param ?int $failures the failed attempts with the password in the window
	 * @param ?int $names the accounts it was tried for: by everyone for a spray, by the address for a joining one
	 * @param ?int $sources the addresses that tried it
	 * @param ?int $banTargets the addresses the ban response blocks
	 * @param ?int $listed the addresses counted for blocking, at most {@see PasswordSpraying::MAX_BAN_TARGETS}
	 * @param ?bool $client a login by an app or script, not the login page
	 */
	public function __construct(
		public ?PasswordSprayingRule $rule = null,
		public ?int $failures = null,
		public ?int $names = null,
		public ?int $sources = null,
		public ?int $banTargets = null,
		public ?int $listed = null,
		public ?bool $client = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			PasswordSprayingRule::tryFrom((string)FactValues::string($stored, 'rule')),
			FactValues::int($stored, 'failures'),
			FactValues::int($stored, 'names'),
			FactValues::int($stored, 'sources'),
			FactValues::int($stored, 'banTargets'),
			FactValues::int($stored, 'listed'),
			FactValues::bool($stored, 'client'),
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return FactValues::recorded([
			'rule' => $this->rule?->value,
			'failures' => $this->failures,
			'names' => $this->names,
			'sources' => $this->sources,
			'banTargets' => $this->banTargets,
			'listed' => $this->listed,
			'client' => $this->client,
		]) + $this->common->toArray();
	}

	/**
	 * The rule stays, the counts are the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$old->rule ?? $new->rule,
			$new->failures ?? $old->failures,
			$new->names ?? $old->names,
			$new->sources ?? $old->sources,
			$new->banTargets ?? $old->banTargets,
			$new->listed ?? $old->listed,
			$new->client ?? $old->client,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
