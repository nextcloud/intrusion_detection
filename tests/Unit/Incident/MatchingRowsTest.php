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
		return static function (?int $after, int $limit) use ($rows, &$calls): array {
			$calls[] = [$after, $limit];
			return array_slice(array_values(array_filter($rows, static fn (int $n): bool => $after === null || $n > $after)), 0, $limit);
		};
	}

	public function testPagesAreReadUntilEnoughRowsMatch(): void {
		$calls = [];
		$even = static fn (int $n): bool => $n % 2 === 0;
		$this->assertSame([0, 2, 4], MatchingRows::collect(self::pages(range(0, 20), $calls), $even, 3));
		$this->assertSame([[null, 3], [2, 3]], $calls, 'the second page was needed, as one row of the first did not match; it starts after the last row of the first');
	}

	public function testAShortPageEndsTheSearch(): void {
		$calls = [];
		$this->assertSame([2], MatchingRows::collect(self::pages([1, 2, 3, 5], $calls), static fn (int $n): bool => $n % 2 === 0, 3));
		$this->assertSame([[null, 3], [3, 3]], $calls);
	}

	public function testNothingMatches(): void {
		$calls = [];
		$this->assertSame([], MatchingRows::collect(self::pages([], $calls), static fn (int $n): bool => true, 5));
		$this->assertCount(1, $calls);
	}

	public function testAtMostMaxPagesAreRead(): void {
		$calls = [];
		$this->assertSame([], MatchingRows::collect(self::pages(range(1, 1000), $calls), static fn (int $n): bool => false, 10));
		$this->assertCount(MatchingRows::MAX_PAGES, $calls);
	}
}
