<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check\Payload;

use OCA\IntrusionDetection\Check\Checks\InjectionProbe;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\Payload\CustomSignatures;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class CustomSignaturesTest extends TestCase {
	private CustomSignatures $custom;

	protected function setUp(): void {
		parent::setUp();
		$this->custom = new CustomSignatures();
	}

	public function testParsesWeightAndPattern(): void {
		$signature = $this->custom->parse('2:union\s{1,3}distinct');
		$this->assertNotNull($signature);
		$this->assertSame(2, $signature->weight);
		$this->assertTrue($signature->custom);
		$this->assertSame(1, preg_match($signature->pattern, 'UNION  DISTINCT'), 'Custom signatures are case-insensitive');
		$this->assertSame(CustomSignatures::idFor('2:union\s{1,3}distinct'), $signature->id);
		$this->assertStringStartsWith('custom_', $signature->id);
	}

	public function testWeightDefaultsToThree(): void {
		$this->assertSame(3, $this->custom->parse('drop\s+table')?->weight);
		// A pattern that starts with digits and a colon needs an explicit weight.
		$this->assertSame(3, $this->custom->parse('3:1:2')?->weight);
	}

	public function testDelimitersNeedNoEscaping(): void {
		$signature = $this->custom->parse('~/#!@');
		$this->assertNotNull($signature);
		$this->assertSame(1, preg_match($signature->pattern, 'x~/#!@y'));
	}

	/**
	 * @return array<string, array{string, ?string}>
	 */
	public static function entries(): array {
		return [
			'good' => ['union\s+distinct\s+select', null],
			'does not compile' => ['union(select', CustomSignatures::PROBLEM_INVALID],
			'ends with a backslash' => ['union\\', CustomSignatures::PROBLEM_INVALID],
			'empty' => ['', CustomSignatures::PROBLEM_INVALID],
			'control character' => ["union\x02select", CustomSignatures::PROBLEM_INVALID],
			'matches everything' => ['a*', CustomSignatures::PROBLEM_MATCHES_EVERYTHING],
			'matches everything with a weight' => ['2:.{0,3}', CustomSignatures::PROBLEM_MATCHES_EVERYTHING],
			'too long' => [str_repeat('a', CustomSignatures::MAX_LENGTH + 1), CustomSignatures::PROBLEM_TOO_LONG],
			'nested quantifier' => ['(a+)+$', CustomSignatures::PROBLEM_TOO_SLOW],
			'alternation that overlaps' => ['(a|aa)+!$', CustomSignatures::PROBLEM_TOO_SLOW],
			'repeated wildcard' => ['(.*a){12}x', CustomSignatures::PROBLEM_TOO_SLOW],
			'words with optional spaces' => ['(\\w+\\s?)+$', CustomSignatures::PROBLEM_TOO_SLOW],
		];
	}

	#[DataProvider('entries')]
	public function testProblem(string $entry, ?string $expected): void {
		$this->assertSame($expected, $this->custom->problem($entry));
		if ($expected !== null && $expected !== CustomSignatures::PROBLEM_TOO_SLOW) {
			$this->assertNull($this->custom->parse($entry), 'An unusable entry is skipped at runtime');
		}
	}

	public function testReadsSkipTheTimingTest(): void {
		$this->assertNull($this->custom->problem('(a+)+$', false));
		$this->assertSame(CustomSignatures::PROBLEM_INVALID, $this->custom->problem('union(select', false));
	}

	public function testValidateThrowsATranslatableReason(): void {
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		try {
			$this->custom->validate(['union\s+select', '(a+)+$']);
			$this->fail('A slow pattern must be refused');
		} catch (InvalidParamException $e) {
			$this->assertSame('invalid_pattern', $e->reason);
			$this->assertSame(CustomSignatures::PROBLEM_TOO_SLOW, $e->details['why']);
			$this->assertStringContainsString('too slow', $e->describe($l));
		}
		$this->expectException(InvalidParamException::class);
		$this->custom->validate(array_fill(0, CustomSignatures::MAX_ITEMS + 1, 'x'));
	}

	public function testThePatternsBacktrackingLimitIsRestored(): void {
		$before = ini_get('pcre.backtrack_limit');
		$this->assertFalse(CustomSignatures::run('/(a+)+$/', str_repeat('a', 30000) . 'b'));
		$this->assertSame($before, ini_get('pcre.backtrack_limit'));
	}

	public function testTheCheckParameterValidatesThoroughlyOnlyWhenSaving(): void {
		$param = (new InjectionProbe())->definition()->param(InjectionProbe::PARAM_CUSTOM);
		$this->assertSame(['(a+)+$'], $param->validate(['(a+)+$']), 'Reads only check that a pattern compiles');
		$this->assertSame(['union\s+select'], $param->validate(['union\s+select'], true));
		$this->expectException(InvalidParamException::class);
		$param->validate(['(a+)+$'], true);
	}

	public function testOccCanSetPatternsWithCommasAsJson(): void {
		$param = (new InjectionProbe())->definition()->param(InjectionProbe::PARAM_CUSTOM);
		$this->assertSame(['union\s{1,3}select', 'drop'], $param->parse('["union\\\\s{1,3}select", "drop"]'));
		$this->assertSame(['a', 'b'], $param->parse('a, b'));
		$this->expectException(InvalidParamException::class);
		$param->parse('[not json');
	}
}
