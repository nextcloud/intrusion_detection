<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check;

use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamType;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class ParamDefinitionTest extends TestCase {
	public function testIntWithinBounds(): void {
		$p = new ParamDefinition('min_failures', ParamType::Int, 10, min: 3, max: 1000);
		$this->assertSame(3, $p->validate(3));
		$this->assertSame(1000, $p->validate('1000'));
	}

	public function testIntBelowMinimumIsRejected(): void {
		$p = new ParamDefinition('min_failures', ParamType::Int, 10, min: 3, max: 1000);
		$this->expectException(InvalidParamException::class);
		$p->validate(2);
	}

	public function testIntAboveMaximumIsRejected(): void {
		$p = new ParamDefinition('min_failures', ParamType::Int, 10, min: 3, max: 1000);
		try {
			$p->validate(1001);
			$this->fail('Expected an exception');
		} catch (InvalidParamException $e) {
			$this->assertSame('too_large', $e->reason);
			$this->assertSame(1000, $e->details['max']);
		}
	}

	public function testFloatsAndNonNumbersAreNotIntegers(): void {
		$p = new ParamDefinition('n', ParamType::Int, 1);
		$this->expectException(InvalidParamException::class);
		$p->validate('1.5');
	}

	/**
	 * @return list<array{string, int}>
	 */
	public static function durations(): array {
		return [
			['90', 90],
			['90s', 90],
			['10m', 600],
			['4h', 14400],
			['7d', 604800],
			[' 2H ', 7200],
		];
	}

	#[DataProvider('durations')]
	public function testParseDuration(string $raw, int $seconds): void {
		$this->assertSame($seconds, ParamDefinition::parseDuration($raw));
	}

	public function testParseDurationRejectsGarbage(): void {
		$this->expectException(InvalidParamException::class);
		ParamDefinition::parseDuration('ten minutes');
	}

	public function testDurationParamParsesUnits(): void {
		$p = new ParamDefinition('window', ParamType::Duration, 600, min: 60, max: 3600);
		$this->assertSame(900, $p->parse('15m'));
	}

	public function testBoolAcceptsCommonSpellings(): void {
		$p = new ParamDefinition('flag', ParamType::Bool, false);
		$this->assertTrue($p->parse('yes'));
		$this->assertTrue($p->parse('ON'));
		$this->assertFalse($p->parse('0'));
		$this->expectException(InvalidParamException::class);
		$p->parse('maybe');
	}

	public function testChoice(): void {
		$p = new ParamDefinition('policy', ParamType::Choice, 'refuse', choices: ['refuse', 'allow_notify']);
		$this->assertSame('allow_notify', $p->validate('allow_notify'));
		$this->expectException(InvalidParamException::class);
		$p->validate('allow');
	}

	public function testStringListTrimsDeduplicatesAndChecksPattern(): void {
		$p = new ParamDefinition('names', ParamType::StringList, [], itemPattern: '/^[a-z]+$/');
		$this->assertSame(['admin', 'root'], $p->validate([' admin', 'root', 'admin']));
		$this->assertSame(['admin', 'root'], $p->parse('admin, root,,'));
		$this->expectException(InvalidParamException::class);
		$p->validate(['Admin!']);
	}

	public function testStringListRejectsControlCharacters(): void {
		$p = new ParamDefinition('names', ParamType::StringList, []);
		$this->expectException(InvalidParamException::class);
		$p->validate(["admin\nroot"]);
	}

	public function testStringListLimitsItems(): void {
		$p = new ParamDefinition('names', ParamType::StringList, [], maxItems: 2);
		$this->expectException(InvalidParamException::class);
		$p->validate(['a', 'b', 'c']);
	}

	public function testCidrListAcceptsRangesAndSingleAddresses(): void {
		$p = new ParamDefinition('office', ParamType::CidrList, []);
		$this->assertSame(['198.51.100.0/24', '2001:db8::/32', '203.0.113.7/32', '2001:db8::1/128'], $p->validate(['198.51.100.0/24', '2001:DB8::/32', '203.0.113.7', '2001:db8::1']));
	}

	/**
	 * @return list<array{string}>
	 */
	public static function invalidRanges(): array {
		return [['198.51.100.0/33'], ['2001:db8::/129'], ['example.org/24'], ['198.51.100'], ['/24']];
	}

	#[DataProvider('invalidRanges')]
	public function testCidrListRejectsInvalidRanges(string $range): void {
		$p = new ParamDefinition('office', ParamType::CidrList, []);
		$this->expectException(InvalidParamException::class);
		$p->validate([$range]);
	}

	public function testInvalidDefaultIsRejectedAtDefinitionTime(): void {
		$this->expectException(InvalidParamException::class);
		new ParamDefinition('n', ParamType::Int, 5, min: 10);
	}

	public function testInvalidNameIsRejected(): void {
		$this->expectException(\InvalidArgumentException::class);
		new ParamDefinition('Bad-Name', ParamType::Int, 1);
	}

	public function testJsonAcceptsObjectsAndListsAndKeepsThemAsText(): void {
		$p = new ParamDefinition('doc', ParamType::Json, '[]');
		$this->assertSame('{"a":1}', $p->validate('{"a":1}'));
		$this->assertSame('[{"id":"x"}]', $p->validate([['id' => 'x']]));
		$this->assertSame('[1,2]', $p->parse(' [1,2] '));
	}

	/**
	 * @return list<array{mixed}>
	 */
	public static function invalidJson(): array {
		return [['{broken'], ['"a string"'], ['42'], ['null'], [42], [true], [str_repeat(' ', ParamDefinition::MAX_JSON_LENGTH) . '[]'], [str_repeat('[', 40) . str_repeat(']', 40)]];
	}

	#[DataProvider('invalidJson')]
	public function testJsonRejectsEverythingElse(mixed $value): void {
		$p = new ParamDefinition('doc', ParamType::Json, '[]');
		$this->expectExceptionObject(new InvalidParamException('not_json', ['param' => 'doc']));
		$p->validate($value);
	}

}
