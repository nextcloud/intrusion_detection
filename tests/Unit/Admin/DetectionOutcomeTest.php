<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Admin;

use OCA\IntrusionDetection\Admin\DetectionPresenter;
use OCA\IntrusionDetection\Db\Detection;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class DetectionOutcomeTest extends TestCase {
	/**
	 * @return array<string, array{bool, list<array{type: string, enforced: bool}>, string}>
	 */
	public static function outcomes(): array {
		return [
			'observed: the check only observes' => [false, [['type' => 'ban', 'enforced' => false]], 'observed'],
			'acted: an address was blocked' => [true, [['type' => 'notify_admin', 'enforced' => true], ['type' => 'ban', 'enforced' => true]], 'acted'],
			'notified: only the administrators were told' => [true, [['type' => 'notify_admin', 'enforced' => true]], 'notified'],
			'recorded: nothing was done' => [true, [], 'recorded'],
			'recorded: an action that was not taken' => [true, [['type' => 'ban', 'enforced' => false]], 'recorded'],
			'an unknown action type is ignored' => [true, [['type' => 'gone', 'enforced' => true]], 'recorded'],
		];
	}

	/**
	 * @param list<array{type: string, enforced: bool}> $actions
	 */
	#[DataProvider('outcomes')]
	public function testTheOutcomeSaysWhatNextcloudDid(bool $enforced, array $actions, string $expected): void {
		$detection = new Detection();
		$detection->setEnforced($enforced);
		$detection->setActionList($actions);
		$this->assertSame($expected, DetectionPresenter::outcome($detection));
	}
}
