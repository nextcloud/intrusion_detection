<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\AccountTakeover;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactsMerger;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What an account takeover detection recorded: the security changes it
 * counted, their points, and the risky login they followed.
 */
final readonly class AccountTakeoverFacts implements IMergeableFacts {
	/**
	 * @param list<AccountTakeoverRule> $rules the rules the changes reached
	 * @param int $anyPoints the points of the changes from all sessions
	 * @param int $sessionPoints the points of the changes in the session of a risky login
	 * @param ?int $riskyLoginAt when that login was
	 * @param ?string $riskyLoginReason why it was risky
	 * @param list<string> $riskyLoginPolicies the step-up policies it needed
	 * @param list<array<array-key, mixed>> $changes the changes: id, type, points, at, ip, old and new
	 * @param ?int $emailChangeId the first change of the email address, when it had one before
	 * @param ?int $emailChangedAt when it was changed
	 * @param ?string $previousAddress the masked address before
	 * @param ?bool $userHasEmail the account has an email address now
	 * @param ?int $sessionTokenId the session the changes were made in
	 */
	public function __construct(
		public array $rules = [],
		public int $anyPoints = 0,
		public int $sessionPoints = 0,
		public ?int $riskyLoginAt = null,
		public ?string $riskyLoginReason = null,
		public array $riskyLoginPolicies = [],
		public array $changes = [],
		public ?int $emailChangeId = null,
		public ?int $emailChangedAt = null,
		public ?string $previousAddress = null,
		public ?bool $userHasEmail = null,
		public ?int $sessionTokenId = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			array_values(array_filter(array_map(static fn (string $rule): ?AccountTakeoverRule => AccountTakeoverRule::tryFrom($rule), FactValues::strings($stored, 'rules') ?? []))),
			FactValues::int($stored, 'anyPoints') ?? 0,
			FactValues::int($stored, 'sessionPoints') ?? 0,
			FactValues::int($stored, 'riskyLoginAt'),
			FactValues::string($stored, 'riskyLoginReason'),
			FactValues::strings($stored, 'riskyLoginPolicies') ?? [],
			self::changes(FactValues::array($stored, 'changes')),
			FactValues::int($stored, 'emailChangeId'),
			FactValues::int($stored, 'emailChangedAt'),
			FactValues::string($stored, 'previousAddress'),
			FactValues::bool($stored, 'userHasEmail'),
			FactValues::int($stored, 'sessionTokenId'),
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'rules' => array_map(static fn (AccountTakeoverRule $rule): string => $rule->value, $this->rules),
			'anyPoints' => $this->anyPoints,
			'sessionPoints' => $this->sessionPoints,
			'riskyLoginAt' => $this->riskyLoginAt,
			'riskyLoginReason' => $this->riskyLoginReason,
			'riskyLoginPolicies' => $this->riskyLoginPolicies,
			'changes' => $this->changes,
			'emailChangeId' => $this->emailChangeId,
			'emailChangedAt' => $this->emailChangedAt,
			'previousAddress' => $this->previousAddress,
			'sessionTokenId' => $this->sessionTokenId,
		] + FactValues::recorded([
			'userHasEmail' => $this->userHasEmail,
		]) + $this->common->toArray();
	}

	/**
	 * The rules, policies and changes of every hit; the rest is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			FactsMerger::union($old->rules, $new->rules) ?? [],
			$new->anyPoints,
			$new->sessionPoints,
			$new->riskyLoginAt,
			$new->riskyLoginReason,
			FactsMerger::union($old->riskyLoginPolicies, $new->riskyLoginPolicies) ?? [],
			FactsMerger::union($old->changes, $new->changes) ?? [],
			$new->emailChangeId,
			$new->emailChangedAt,
			$new->previousAddress,
			$new->userHasEmail ?? $old->userHasEmail,
			$new->sessionTokenId,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}

	/**
	 * @param ?array<array-key, mixed> $changes
	 * @return list<array<array-key, mixed>>
	 */
	private static function changes(?array $changes): array {
		return array_values(array_filter($changes ?? [], 'is_array'));
	}
}
