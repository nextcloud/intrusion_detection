<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Risk;

use OCA\IntrusionDetection\Risk\RiskAssessment;
use OCA\IntrusionDetection\Risk\RiskLimits;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class RiskAssessmentTest extends TestCase {
	/**
	 * @return array<string, array{int, string, float}>
	 */
	public static function tiers(): array {
		return [
			'nothing' => [0, RiskAssessment::TIER_NORMAL, 1.0],
			'one point' => [1, RiskAssessment::TIER_NORMAL, 1.0],
			'elevated from 2' => [2, RiskAssessment::TIER_ELEVATED, 0.5],
			'still elevated at 3' => [3, RiskAssessment::TIER_ELEVATED, 0.5],
			'high from 4' => [4, RiskAssessment::TIER_HIGH, 0.25],
			'far above' => [15, RiskAssessment::TIER_HIGH, 0.25],
			'office network' => [-10, RiskAssessment::TIER_NORMAL, 1.0],
		];
	}

	#[DataProvider('tiers')]
	public function testTheScoreFallsIntoItsTier(int $score, string $tier, float $factor): void {
		$risk = RiskAssessment::of($score === 0 ? [] : [['fact' => 'x', 'points' => $score, 'detail' => null]], 2, 4, 0.5, 0.25);
		$this->assertSame($score, $risk->score);
		$this->assertSame($tier, $risk->tier);
		$this->assertSame($factor, $risk->factor);
		$this->assertSame($tier === RiskAssessment::TIER_HIGH, $risk->isHigh());
	}

	public function testTheScoreIsTheSumOfItsParts(): void {
		$risk = RiskAssessment::of([
			['fact' => RiskAssessment::FACT_HOSTING, 'points' => 1, 'detail' => null],
			['fact' => RiskAssessment::FACT_ATTACK_TOOL, 'points' => 2, 'detail' => 'curl'],
			['fact' => RiskAssessment::FACT_OFFICE, 'points' => -10, 'detail' => '203.0.113.0/24'],
		], 2, 4, 0.5, 0.25);
		$this->assertSame(-7, $risk->score);
		$this->assertSame(RiskAssessment::TIER_NORMAL, $risk->tier);
	}

	public function testAHighTierBelowTheElevatedOneStillWins(): void {
		$risk = RiskAssessment::of([['fact' => 'x', 'points' => 3, 'detail' => null]], 5, 3, 0.5, 0.25);
		$this->assertSame(RiskAssessment::TIER_HIGH, $risk->tier);
	}

	/**
	 * @return array<string, array{int, float, int}>
	 */
	public static function limits(): array {
		return [
			'halved' => [10, 0.5, 5],
			'quartered, rounded up' => [10, 0.25, 3],
			'never below 2' => [5, 0.25, 2],
			'a limit of 2 stays' => [2, 0.25, 2],
			'below the floor stays' => [1, 0.25, 1],
			'factor 1 changes nothing' => [10, 1.0, 10],
			'exact products are not rounded up' => [20, 0.25, 5],
			'large numbers' => [1000, 0.05, 50],
		];
	}

	#[DataProvider('limits')]
	public function testLimitsAreMultipliedWithAFloorOfTwo(int $limit, float $factor, int $expected): void {
		$this->assertSame($expected, RiskAssessment::lowerBy($limit, $factor));
	}

	public function testTheNeutralAssessmentChangesNothing(): void {
		$risk = RiskAssessment::neutral();
		$this->assertSame(0, $risk->score);
		$this->assertSame(10, $risk->lower(10));
		$this->assertFalse($risk->isHigh());
	}

	public function testItSurvivesBeingStored(): void {
		$risk = RiskAssessment::of([
			['fact' => RiskAssessment::FACT_TOR, 'points' => 2, 'detail' => null],
			['fact' => RiskAssessment::FACT_FAILURES, 'points' => 2, 'detail' => '11'],
		], 2, 4, 0.5, 0.25);
		$stored = json_decode((string)json_encode($risk->toArray()), true);
		$this->assertEquals($risk, RiskAssessment::fromArray($stored));
	}

	public function testBrokenStoredDataIsNoAssessment(): void {
		$this->assertNull(RiskAssessment::fromArray(null));
		$this->assertNull(RiskAssessment::fromArray(['score' => 'high']));
		$this->assertNull(RiskAssessment::fromArray(['score' => 2]));
		$partial = RiskAssessment::fromArray(['score' => 2, 'tier' => 'nonsense', 'parts' => [['fact' => 'tor'], 'x', ['fact' => 'tor', 'points' => 2, 'detail' => ['x']]]]);
		$this->assertNotNull($partial);
		$this->assertSame(RiskAssessment::TIER_NORMAL, $partial->tier);
		$this->assertSame([['fact' => 'tor', 'points' => 2, 'detail' => null]], $partial->parts);
	}

	public function testLimitsReachAndTellWhatWasLowered(): void {
		$risk = RiskAssessment::of([['fact' => RiskAssessment::FACT_TOR, 'points' => 3, 'detail' => null]], 2, 4, 0.5, 0.25);
		$limits = new RiskLimits(['min_failures' => 10, 'min_names' => 2], ['min_failures' => 5, 'min_names' => 2], ['min_failures' => 6, 'min_names' => 2], $risk);
		$this->assertTrue($limits->reached());
		$this->assertTrue($limits->isLowered());
		$this->assertSame(5, $limits->of('min_failures'));
		$this->assertSame([
			RiskAssessment::FACTS_KEY => $risk->toArray(),
			RiskLimits::FACTS_KEY => ['min_failures' => ['plain' => 10, 'effective' => 5]],
		], $limits->facts());

		$plain = new RiskLimits(['min_failures' => 10], ['min_failures' => 10], ['min_failures' => 6], null);
		$this->assertFalse($plain->reached());
		$this->assertSame([], $plain->facts());
	}
}
