<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\AdminChange;

use OCA\IntrusionDetection\AdminChange\DisplayValue;
use OCA\IntrusionDetection\AdminChange\WatchedValue;
use Test\TestCase;

class DisplayValueTest extends TestCase {
	public function testScalarsStayAsTheyAre(): void {
		$this->assertSame(true, DisplayValue::shorten(true));
		$this->assertSame(2, DisplayValue::shorten(2));
		$this->assertNull(DisplayValue::shorten(null));
		$this->assertSame('cloud.example.com', DisplayValue::shorten('cloud.example.com'));
	}

	public function testLongTextIsCutAndControlCharactersRemoved(): void {
		$short = DisplayValue::shorten(str_repeat('a', 500));
		$this->assertSame(DisplayValue::MAX_TEXT, mb_strlen($short));
		$this->assertStringEndsWith('…', $short);
		$this->assertSame('a b', DisplayValue::shorten("a\r\nb"));
	}

	public function testListsAreCut(): void {
		$list = DisplayValue::shorten(range(1, 50));
		$this->assertCount(DisplayValue::MAX_ITEMS + 1, $list);
		$this->assertSame('…', end($list));
	}

	public function testMapsAndNestedValuesBecomeText(): void {
		$this->assertSame(['host: a', '["x","y"]'], DisplayValue::shorten(['host' => 'a', ['x', 'y']]));
	}

	public function testEncodeAndDecodeRoundTrip(): void {
		$this->assertSame(['10.0.0.1', '10.0.0.2'], DisplayValue::decode(DisplayValue::encode(['10.0.0.1', '10.0.0.2'])));
		$this->assertNull(DisplayValue::decode(null));
		$this->assertNull(DisplayValue::decode('not json'));
	}

	public function testSecretValuesHaveNoDisplayValue(): void {
		$this->assertNull((new WatchedValue('system:x', 'hunter2', true, true))->display());
		$this->assertSame('"cloud"', (new WatchedValue('system:x', 'cloud', false, true))->display());
	}

	public function testTheCanonicalFormTellsTypesApart(): void {
		$this->assertNotSame(WatchedValue::canonicalOf('1'), WatchedValue::canonicalOf(1));
		$this->assertNotSame(WatchedValue::canonicalOf(null), WatchedValue::canonicalOf(''));
		$this->assertNotSame(WatchedValue::canonicalOf("\xff"), WatchedValue::canonicalOf("\xfe"), 'Invalid UTF-8 is hashed exactly');
	}
}
