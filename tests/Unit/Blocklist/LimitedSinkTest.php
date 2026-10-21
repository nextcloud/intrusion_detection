<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Blocklist;

use OCA\IntrusionDetection\Blocklist\LimitedSink;
use OCA\IntrusionDetection\Blocklist\SyncFailure;
use Test\TestCase;

class LimitedSinkTest extends TestCase {
	public function testKeepsWhatFitsAndReadsItBack(): void {
		$sink = new LimitedSink(10);
		$this->assertSame(4, $sink->write('abcd'));
		$this->assertSame(6, $sink->write('efghij'));
		$this->assertSame(10, $sink->getSize());
		$this->assertSame('abcdefghij', (string)$sink);
		$sink->rewind();
		$this->assertSame('abc', $sink->read(3));
		$this->assertSame(3, $sink->tell());
		$this->assertTrue($sink->isWritable() && $sink->isReadable() && $sink->isSeekable());
	}

	public function testRefusesTheFirstByteOverTheLimit(): void {
		$sink = new LimitedSink(10);
		$sink->write('abcdefghij');
		try {
			$sink->write('k');
			$this->fail('The limit must hold');
		} catch (SyncFailure $e) {
			$this->assertSame(SyncFailure::TOO_LARGE, $e->reason);
		}
		$this->assertSame('abcdefghij', (string)$sink);
	}

	public function testAClosedSinkCannotBeUsed(): void {
		$sink = new LimitedSink(10);
		$sink->close();
		$this->assertFalse($sink->isWritable());
		$this->assertSame('', (string)$sink);
		$this->expectException(\RuntimeException::class);
		$sink->write('a');
	}
}
