<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Perf;

use OCA\IntrusionDetection\Perf\FreshRequestProbe;
use Test\TestCase;

class FreshRequestProbeTest extends TestCase {
	public function testAChildThatPrintsIsRead(): void {
		$this->assertSame('{"ok":1}', self::invokePrivate(FreshRequestProbe::class, 'runChild', ['echo \'{"ok":1}\';', 5]));
	}

	public function testAFailingChildGivesNothing(): void {
		$this->assertNull(self::invokePrivate(FreshRequestProbe::class, 'runChild', ['exit(3);', 5]));
	}

	public function testAHangingChildIsKilledAfterTheTimeout(): void {
		$start = microtime(true);
		$this->assertNull(self::invokePrivate(FreshRequestProbe::class, 'runChild', ['sleep(30);', 1]));
		$this->assertLessThan(10, microtime(true) - $start, 'the command does not wait for the child');
	}
}
