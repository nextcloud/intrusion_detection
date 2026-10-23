<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\ResetProbing;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a reset probing detection recorded: the password reset requests of
 * one address for many accounts, or of many addresses for one account.
 * Counts are estimates when attempts were sampled.
 */
final readonly class ResetProbingFacts implements IMergeableFacts {
	/**
	 * @param ?int $inputs the different names or email addresses one address asked for
	 * @param int $requests the reset requests within the window
	 * @param int $sampleFactor one in this many attempts was recorded
	 * @param ?int $sources the addresses that asked for one account
	 * @param ?string $lastSource the address of the most recent request for one account
	 */
	public function __construct(
		public ?ResetProbingRule $rule = null,
		public ?int $inputs = null,
		public int $requests = 0,
		public int $sampleFactor = 1,
		public ?int $sources = null,
		public ?string $lastSource = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			ResetProbingRule::tryFrom((string)FactValues::string($stored, 'rule')),
			FactValues::int($stored, 'inputs'),
			FactValues::int($stored, 'requests') ?? 0,
			FactValues::int($stored, 'sampleFactor') ?? 1,
			FactValues::int($stored, 'sources'),
			FactValues::string($stored, 'lastSource'),
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'requests' => $this->requests,
			'sampleFactor' => $this->sampleFactor,
		] + FactValues::recorded([
			'rule' => $this->rule?->value,
			'inputs' => $this->inputs,
			'sources' => $this->sources,
			'lastSource' => $this->lastSource,
		]) + $this->common->toArray();
	}

	/**
	 * The rule stays, the counts are the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$old->rule ?? $new->rule,
			$new->inputs ?? $old->inputs,
			$new->requests,
			$new->sampleFactor,
			$new->sources ?? $old->sources,
			$new->lastSource ?? $old->lastSource,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
