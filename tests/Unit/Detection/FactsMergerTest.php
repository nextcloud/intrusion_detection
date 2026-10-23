<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Detection;

use OCA\IntrusionDetection\Check\Checks\AccountLocked\AccountLockedFacts;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffingFacts;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffingRule;
use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\Explanation;
use OCA\IntrusionDetection\Detection\FactsMerger;
use Test\TestCase;

class FactsMergerTest extends TestCase {
	public function testTheFactsClassMergesItsFacts(): void {
		$hit = new CredentialStuffingFacts(CredentialStuffingRule::Network, failures: 9, common: new CommonFacts(first: 150, last: 300, targets: ['bob', 'carol']));
		$merged = FactsMerger::merge(
			['rule' => 'source', 'failures' => 7, 'first' => 100, 'last' => 200, 'targets' => ['alice', 'bob'], 'old' => 'kept'],
			new DetectionDraft('credential_stuffing', facts: $hit),
		);
		$this->assertSame('source', $merged['rule'], 'The original rule stays');
		$this->assertSame(9, $merged['failures'], 'Counts are the latest');
		$this->assertSame(100, $merged['first']);
		$this->assertSame(300, $merged['last']);
		$this->assertSame(['alice', 'bob', 'carol'], $merged['targets'], 'Earlier accounts are kept');
		$this->assertSame('kept', $merged['old'], 'Stored facts the class does not know stay');
	}

	public function testFactsThatDeclareNoMergeAreTheLatest(): void {
		$merged = FactsMerger::merge(['link' => '1', 'old' => 'kept'], new DetectionDraft('account_locked', facts: new AccountLockedFacts(link: '2')));
		$this->assertSame('2', $merged['link']);
		$this->assertSame('kept', $merged['old']);
		$this->assertSame(['old' => 'kept'], FactsMerger::merge(['old' => 'kept'], new DetectionDraft('manual_block')), 'A draft without facts changes nothing');
	}

	public function testListsAreBounded(): void {
		$old = array_map(static fn (int $i): string => 'user' . $i, range(1, Explanation::MAX_TARGETS));
		$this->assertSame($old, FactsMerger::union($old, ['newcomer'], Explanation::MAX_TARGETS));
		$this->assertSame(range(1, FactsMerger::MAX_LIST), FactsMerger::union(range(1, 40), range(30, 80)));
	}

	public function testListsOfStructuresAreJoinedByValue(): void {
		$this->assertSame([['group' => 'a'], ['group' => 'b']], FactsMerger::union([['group' => 'a']], [['group' => 'a'], ['group' => 'b']]));
	}

	public function testAMissingListIsNoList(): void {
		$this->assertSame(['a'], FactsMerger::union(null, ['a']));
		$this->assertSame(['a'], FactsMerger::union(['a'], null));
		$this->assertNull(FactsMerger::union(null, null));
	}
}
