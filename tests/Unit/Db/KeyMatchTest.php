<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Db;

use OCA\IntrusionDetection\Db\KeyMatch;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class KeyMatchTest extends TestCase {
	/**
	 * @return array<string, array{list<string>, string}>
	 */
	public static function prefixes(): array {
		return [
			'the addresses of a /24' => [['198.51.100._', '198.51.100.__', '198.51.100.___'], '198.51.100.'],
			'the /64s of a /48' => [['2001:db8:1:%::/64'], '2001:db8:1:'],
			'the /64s of a /56 with a high byte' => [['2001:db8:1:2a__::/64'], '2001:db8:1:2a'],
			'patterns that share less' => [['abc%', 'abd%'], 'ab'],
			'an escaped wildcard ends the prefix' => [['ab\\_c%'], 'ab'],
			'nothing in common' => [['a%', 'b%'], ''],
			'no patterns' => [[], ''],
		];
	}

	/**
	 * @param list<string> $patterns
	 */
	#[DataProvider('prefixes')]
	public function testThePatternsShareTheirLiteralStart(array $patterns, string $prefix): void {
		$this->assertSame($prefix, (new KeyMatch([], $patterns))->prefix());
	}

	public function testEveryKeyCharacterSortsBelowTheEndOfTheRange(): void {
		foreach (str_split('0123456789abcdef.:/') as $char) {
			$this->assertLessThan(0, strcmp($char, KeyMatch::RANGE_END), $char);
		}
	}
}
