<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Risk\RiskAssessment;
use OCA\IntrusionDetection\Risk\RiskLimits;

/**
 * The facts that detections of many checks record, and that code outside
 * the check reads: when the attack began and last went on, the accounts it
 * tried, the address risk score with the limits it lowered, the sessions
 * it is about, and whether the detection is a simulation. Each check's
 * facts class holds one.
 */
final readonly class CommonFacts {
	/** The sessions a detection is about, also linked later ({@see \OCA\IntrusionDetection\Confirm\LoginDetections}) */
	public const SESSION_TOKEN_IDS = 'sessionTokenIds';

	/** @var ?list<string> */
	public ?array $targets;

	/**
	 * @param ?list<string> $targets the accounts the attack tried, unique, at most {@see Explanation::MAX_TARGETS}
	 * @param array<string, mixed> $risk the score and the lowered limits, as {@see RiskLimits::facts()} gives them
	 * @param ?list<int> $sessionTokenIds the ids of the session tokens the detection is about
	 */
	public function __construct(
		public ?int $first = null,
		public ?int $last = null,
		?array $targets = null,
		public array $risk = [],
		public bool $simulated = false,
		public ?array $sessionTokenIds = null,
	) {
		$this->targets = $targets === null ? null : array_slice(array_values(array_unique(array_map('strval', $targets))), 0, Explanation::MAX_TARGETS);
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::int($stored, 'first'),
			FactValues::int($stored, 'last'),
			FactValues::strings($stored, 'targets'),
			array_intersect_key($stored, [RiskAssessment::FACTS_KEY => true, RiskLimits::FACTS_KEY => true]),
			FactValues::bool($stored, 'simulated') ?? false,
			FactValues::ints($stored, self::SESSION_TOKEN_IDS),
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	public function toArray(): array {
		return FactValues::recorded(['first' => $this->first, 'last' => $this->last, 'targets' => $this->targets, self::SESSION_TOKEN_IDS => $this->sessionTokenIds])
			+ $this->risk
			+ ($this->simulated ? ['simulated' => true] : []);
	}

	/**
	 * The earliest beginning, the latest end, the accounts and sessions of
	 * both in the order they were first seen, and the latest risk score.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$old->first !== null && $new->first !== null ? min($old->first, $new->first) : $new->first ?? $old->first,
			$old->last !== null && $new->last !== null ? max($old->last, $new->last) : $new->last ?? $old->last,
			FactsMerger::union($old->targets, $new->targets, Explanation::MAX_TARGETS),
			array_replace($old->risk, $new->risk),
			$old->simulated || $new->simulated,
			FactsMerger::union($old->sessionTokenIds, $new->sessionTokenIds),
		);
	}
}
