<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Detection;

use OCA\IntrusionDetection\Detection\Explanation;
use OCA\IntrusionDetection\Detection\FactsMerger;
use Test\TestCase;

class FactsMergerTest extends TestCase {
	public function testEachKindOfFactIsMergedItsOwnWay(): void {
		$merged = FactsMerger::merge(
			['rule' => 'spray', 'first' => 100, 'last' => 200, 'targets' => ['alice', 'bob'], 'failures' => 7, 'risk' => ['score' => 10], 'old' => 'kept'],
			['rule' => 'flagged', 'first' => 150, 'last' => 300, 'targets' => ['bob', 'carol'], 'failures' => 9, 'risk' => ['score' => 40], 'lastSource' => '198.51.100.8'],
		);
		$this->assertSame('spray', $merged['rule'], 'The original rule stays');
		$this->assertSame(100, $merged['first']);
		$this->assertSame(300, $merged['last']);
		$this->assertSame(['alice', 'bob', 'carol'], $merged['targets'], 'Earlier accounts are kept');
		$this->assertSame(9, $merged['failures'], 'Counts are the latest');
		$this->assertSame(['score' => 40], $merged['risk']);
		$this->assertSame('kept', $merged['old']);
		$this->assertSame('198.51.100.8', $merged['lastSource']);
	}

	public function testAnEarlierFirstIsNotMovedForward(): void {
		$this->assertSame(['first' => 100, 'last' => 500], FactsMerger::merge(['first' => 100, 'last' => 500], ['first' => 400, 'last' => 450]));
	}

	public function testListsAreBounded(): void {
		$old = array_map(static fn (int $i): string => 'user' . $i, range(1, Explanation::MAX_TARGETS));
		$merged = FactsMerger::merge(['targets' => $old, 'lists' => range(1, 40)], ['targets' => ['newcomer'], 'lists' => range(30, 80)]);
		$this->assertSame($old, $merged['targets']);
		$this->assertCount(FactsMerger::MAX_LIST, $merged['lists']);
		$this->assertSame(range(1, FactsMerger::MAX_LIST), $merged['lists']);
	}

	public function testListsOfStructuresAreJoinedByValue(): void {
		$merged = FactsMerger::merge(['delegated' => [['group' => 'a']]], ['delegated' => [['group' => 'a'], ['group' => 'b']]]);
		$this->assertSame([['group' => 'a'], ['group' => 'b']], $merged['delegated']);
	}

	public function testAListReplacedByAScalarTakesTheLatest(): void {
		$this->assertSame(['targets' => 'x'], FactsMerger::merge(['targets' => ['a']], ['targets' => 'x']));
		$this->assertSame(['first' => 'later'], FactsMerger::merge(['first' => 5], ['first' => 'later']));
	}
}
