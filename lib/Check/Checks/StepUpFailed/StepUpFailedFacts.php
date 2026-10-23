<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\StepUpFailed;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactsMerger;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a failed login confirmation recorded: how it failed, why the login
 * needed confirmation, and the login it ended.
 */
final readonly class StepUpFailedFacts implements IMergeableFacts {
	/**
	 * @param ?StepUpFailedRule $rule how it failed, null for a rule this version does not know
	 * @param list<string> $policies why the login needed confirmation ({@see \OCA\IntrusionDetection\Confirm\StepUpPolicy})
	 * @param int $attempts the wrong codes entered
	 * @param ?int $started when the login began
	 * @param ?int $ttl the seconds it had to be confirmed in
	 * @param ?int $sessionTokenId the session of the login
	 * @param bool $abandoned the login was left waiting and ended without its session
	 */
	public function __construct(
		public ?StepUpFailedRule $rule = null,
		public array $policies = [],
		public int $attempts = 0,
		public ?int $started = null,
		public ?int $ttl = null,
		public ?int $sessionTokenId = null,
		public bool $abandoned = false,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		$rule = FactValues::string($stored, 'rule');
		return new self(
			$rule === null ? null : StepUpFailedRule::tryFrom($rule),
			FactValues::strings($stored, 'policies') ?? [],
			FactValues::int($stored, 'attempts') ?? 0,
			FactValues::int($stored, 'started'),
			FactValues::int($stored, 'ttl'),
			FactValues::int($stored, 'sessionTokenId'),
			FactValues::bool($stored, 'abandoned') ?? false,
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return FactValues::recorded([
			'rule' => $this->rule?->value,
		]) + [
			'policies' => $this->policies,
			'attempts' => $this->attempts,
		] + FactValues::recorded([
			'started' => $this->started,
			'ttl' => $this->ttl,
		]) + [
			'sessionTokenId' => $this->sessionTokenId,
		] + ($this->abandoned ? ['abandoned' => true] : []) + $this->common->toArray();
	}

	/**
	 * The reasons of every hit; the rest is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$old->rule ?? $new->rule,
			FactsMerger::union($old->policies, $new->policies) ?? [],
			$new->attempts,
			$new->started ?? $old->started,
			$new->ttl ?? $old->ttl,
			$new->sessionTokenId,
			$old->abandoned || $new->abandoned,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
