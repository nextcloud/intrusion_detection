<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check\Payload;

use OCA\IntrusionDetection\Check\Payload\Normalizer;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class NormalizerTest extends TestCase {
	/**
	 * @return array<string, array{string, string}>
	 */
	public static function values(): array {
		return [
			'lower-cased' => ['UNION Select', 'union select'],
			'decoded once' => ['1%27%20OR%201%3D1', "1' or 1=1"],
			'decoded twice' => ['1%2527%2520OR', "1' or"],
			'not decoded a third time' => ['%252527', '%27'],
			'plus is a space' => ['1+UNION+SELECT', '1 union select'],
			'tab and newline' => ['union%09select%0afrom', 'union select from'],
			'whitespace collapsed and trimmed' => ["  a \t\n  b  ", 'a b'],
			'empty comment' => ['1/**/UNION/**/SELECT', '1 union select'],
			'comment with text' => ['union/*foo*/select', 'union select'],
			'executable comment keeps its content' => ['/*!50000UNION*/ SELECT', 'union select'],
			'null bytes removed' => ["un%00ion sel\0ect", 'union select'],
			'invalid UTF-8 survives' => ["\xff\xfeA", "\xff\xfea"],
		];
	}

	#[DataProvider('values')]
	public function testNormalize(string $raw, string $expected): void {
		$this->assertSame($expected, (new Normalizer())->normalize($raw));
	}

	public function testUrlDecodeStopsWhenNothingChanges(): void {
		$this->assertSame('100% sure', Normalizer::urlDecode('100% sure'));
		$this->assertSame('a+b', Normalizer::urlDecode('a%2Bb'), 'A plus stays a plus, so base64 survives');
	}
}
