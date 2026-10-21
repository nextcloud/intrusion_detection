<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Risk;

/**
 * The risk score of one address at one moment (concept section 10.18): the
 * points per fact, their sum, the tier it falls into, and the factor the
 * count limits of the login-failure checks are multiplied by in that tier.
 *
 * Detections store it (fact `risk`), with the tiers in force, so that their
 * explanation stays right after the settings changed.
 *
 * @psalm-type RiskPart = array{fact: string, points: int, detail: ?string}
 */
final class RiskAssessment {
	public const TIER_NORMAL = 'normal';
	public const TIER_ELEVATED = 'elevated';
	public const TIER_HIGH = 'high';

	public const FACT_ATTACK_TOOL = 'attack_tool';
	public const FACT_TOR = 'tor';
	public const FACT_HOSTING = 'hosting';
	public const FACT_BLOCKLIST = 'blocklist';
	public const FACT_TRAP = 'trap';
	public const FACT_FLAGGED = 'flagged';
	public const FACT_FAILURES = 'failures';
	public const FACT_OFFICE = 'office';

	/** A lowered limit is never below this, and limits at or below it are never lowered */
	public const FLOOR = 2;
	/** The detection fact that holds the assessment */
	public const FACTS_KEY = 'risk';

	/**
	 * @param self::TIER_* $tier
	 * @param list<RiskPart> $parts
	 */
	public function __construct(
		public readonly int $score,
		public readonly string $tier,
		public readonly float $factor,
		public readonly array $parts,
		public readonly int $tierElevated,
		public readonly int $tierHigh,
	) {
	}

	/**
	 * The assessment while the risk score is off: nothing changes.
	 */
	public static function neutral(): self {
		return new self(0, self::TIER_NORMAL, 1.0, [], 0, 0);
	}

	/**
	 * @param list<RiskPart> $parts
	 */
	public static function of(array $parts, int $tierElevated, int $tierHigh, float $factorElevated, float $factorHigh): self {
		$score = array_sum(array_column($parts, 'points'));
		[$tier, $factor] = match (true) {
			$score >= $tierHigh => [self::TIER_HIGH, $factorHigh],
			$score >= $tierElevated => [self::TIER_ELEVATED, $factorElevated],
			default => [self::TIER_NORMAL, 1.0],
		};
		return new self($score, $tier, $factor, $parts, $tierElevated, $tierHigh);
	}

	public function isHigh(): bool {
		return $this->tier === self::TIER_HIGH;
	}

	/**
	 * A count limit for this address.
	 */
	public function lower(int $limit): int {
		return self::lowerBy($limit, $this->factor);
	}

	/**
	 * A count limit multiplied by a factor, rounded up, but never below
	 * FLOOR. Limits at or below FLOOR stay as they are.
	 */
	public static function lowerBy(int $limit, float $factor): int {
		if ($factor >= 1.0 || $limit <= self::FLOOR) {
			return $limit;
		}
		return max(self::FLOOR, (int)ceil(round($limit * $factor, 6)));
	}

	/**
	 * @return array{score: int, tier: string, factor: float, parts: list<RiskPart>, tiers: array{elevated: int, high: int}}
	 */
	public function toArray(): array {
		return [
			'score' => $this->score,
			'tier' => $this->tier,
			'factor' => $this->factor,
			'parts' => $this->parts,
			'tiers' => ['elevated' => $this->tierElevated, 'high' => $this->tierHigh],
		];
	}

	/**
	 * An assessment as a detection stored it, or null when it is not one.
	 */
	public static function fromArray(mixed $data): ?self {
		if (!is_array($data) || !is_int($data['score'] ?? null) || !is_array($data['parts'] ?? null)) {
			return null;
		}
		$tier = in_array($data['tier'] ?? null, [self::TIER_NORMAL, self::TIER_ELEVATED, self::TIER_HIGH], true) ? $data['tier'] : self::TIER_NORMAL;
		$parts = [];
		foreach ($data['parts'] as $part) {
			if (is_array($part) && is_string($part['fact'] ?? null) && is_int($part['points'] ?? null)) {
				$detail = $part['detail'] ?? null;
				$parts[] = ['fact' => $part['fact'], 'points' => $part['points'], 'detail' => is_scalar($detail) ? (string)$detail : null];
			}
		}
		$tiers = is_array($data['tiers'] ?? null) ? $data['tiers'] : [];
		$factor = $data['factor'] ?? 1.0;
		return new self(
			$data['score'],
			$tier,
			is_float($factor) || is_int($factor) ? (float)$factor : 1.0,
			$parts,
			is_int($tiers['elevated'] ?? null) ? $tiers['elevated'] : 0,
			is_int($tiers['high'] ?? null) ? $tiers['high'] : 0,
		);
	}
}
