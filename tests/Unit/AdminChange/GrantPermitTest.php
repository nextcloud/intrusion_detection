<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\AdminChange;

use OCA\IntrusionDetection\AdminChange\GrantPermit;
use Test\TestCase;

class GrantPermitTest extends TestCase {
	public function testAPermitIsUsedUpByItsFirstUse(): void {
		$permit = new GrantPermit();
		$permit->allow('bob', 'admin', ['approval' => 7]);
		$this->assertSame(['approval' => 7], $permit->consume('bob', 'admin'));
		$this->assertNull($permit->consume('bob', 'admin'), 'A permit cannot be replayed');
	}

	public function testAPermitIsKeyedToTheExactAccountAndGroup(): void {
		$permit = new GrantPermit();
		$permit->allow('bob', 'admin');
		$this->assertNull($permit->consume('mallory', 'admin'));
		$this->assertNull($permit->consume('bob', 'admins'));
		$this->assertNull($permit->consume('bo', "b\0admin"), 'The key cannot be forged by moving the separator');
		$this->assertSame([], $permit->consume('bob', 'admin'));
	}

	public function testARevokedPermitIsGone(): void {
		$permit = new GrantPermit();
		$permit->allow('bob', 'admin');
		$permit->revoke('bob', 'admin');
		$this->assertNull($permit->consume('bob', 'admin'));
	}

	public function testAPermitLivesOnlyInItsObject(): void {
		(new GrantPermit())->allow('bob', 'admin');
		$this->assertNull((new GrantPermit())->consume('bob', 'admin'));
	}

	public function testTheRevertMarker(): void {
		$permit = new GrantPermit();
		$this->assertFalse($permit->isReverting('bob', 'admin'));
		$permit->beginRevert('bob', 'admin');
		$this->assertTrue($permit->isReverting('bob', 'admin'));
		$this->assertFalse($permit->isReverting('bob', 'other'));
		$permit->endRevert('bob', 'admin');
		$this->assertFalse($permit->isReverting('bob', 'admin'));
	}
}
