<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Incident;

use OCA\IntrusionDetection\Incident\MatchingRows;
use Test\TestCase;

class MatchingRowsTest extends TestCase {
	/**
	 * @param list<int> $rows
	 * @param list<array{int, int}> $calls
	 * @return \Closure(int, int): list<int>
	 */
	private static function pages(array $rows, array &$calls): \Closure {
		return static function (int $offset, int $limit) use ($rows, &$calls): array {
			$calls[] = [$offset, $limit];
			return array_slice($rows, $offset, $limit);
		};
	}

	public function testPagesAreReadUntilEnoughRowsMatch(): void {
		$calls = [];
		$even = static fn (int $n): bool => $n % 2 === 0;
		$this->assertSame([0, 2, 4], MatchingRows::collect(self::pages(range(0, 20), $calls), $even, 3));
		$this->assertSame([[0, 3], [3, 3]], $calls, 'the second page was needed, as one row of the first did not match');
	}

	public function testAShortPageEndsTheSearch(): void {
		$calls = [];
		$this->assertSame([2], MatchingRows::collect(self::pages([1, 2, 3, 5], $calls), static fn (int $n): bool => $n % 2 === 0, 3));
		$this->assertSame([[0, 3], [3, 3]], $calls);
	}

	public function testNothingMatches(): void {
		$calls = [];
		$this->assertSame([], MatchingRows::collect(self::pages([], $calls), static fn (int $n): bool => true, 5));
		$this->assertCount(1, $calls);
	}
}
