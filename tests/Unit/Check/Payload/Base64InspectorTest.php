<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check\Payload;

use OCA\IntrusionDetection\Check\Payload\Base64Inspector;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class Base64InspectorTest extends TestCase {
	private Base64Inspector $inspector;

	protected function setUp(): void {
		parent::setUp();
		$this->inspector = new Base64Inspector();
	}

	public function testStandardBase64WithPadding(): void {
		$this->assertSame(["' OR '1'='1"], $this->inspector->decode('JyBPUiAnMSc9JzE='));
	}

	public function testUrlSafeWithoutPadding(): void {
		$this->assertSame(['UNION SELECT password FROM oc_users'], $this->inspector->decode('VU5JT04gU0VMRUNUIHBhc3N3b3JkIEZST00gb2NfdXNlcnM'));
		$this->assertSame(['<?php ?>?>?>?>'], $this->inspector->decode(rtrim(strtr(base64_encode('<?php ?>?>?>?>'), '+/', '-_'), '=')));
	}

	public function testUrlSafeWithCorrectPadding(): void {
		$encoded = strtr(base64_encode('<?php echo 1;?>>>'), '+/', '-_');
		$this->assertSame('PD9waHAgZWNobyAxOz8-Pj4=', $encoded);
		$this->assertSame(['<?php echo 1;?>>>'], $this->inspector->decode($encoded));
	}

	public function testTwoLevelsAtMost(): void {
		$once = base64_encode("' OR '1'='1 -- and more");
		$twice = base64_encode($once);
		$thrice = base64_encode($twice);
		$this->assertSame([$once, "' OR '1'='1 -- and more"], $this->inspector->decode($twice));
		$this->assertSame([$twice, $once], $this->inspector->decode($thrice));
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function notCandidates(): array {
		return [
			'too short' => ['dGVzdA=='],
			'standard alphabet with wrong padding' => ['JyBPUiAnMSc9JzE'],
			'wrong padding length' => ['JyBPUiAnMSc9JzE=='],
			'padding in the middle' => ['JyBPUi=AnMSc9JzE='],
			'mixed alphabets' => ['JyBPUiAnM+c9Jz_E'],
			'one character left over' => ['VU5JT04gU0VMRUNUIHBhc3N3b3JkIEZST00gb2NfdXNlc'],
			'not canonical' => ['JyBPUiAnMSc9JzF='],
			'too long' => [str_repeat('QUJD', 2049)],
			'spaces' => ['JyBPUiAn MSc9JzE='],
		];
	}

	#[DataProvider('notCandidates')]
	public function testRejectsWhatIsNotACandidate(string $value): void {
		$this->assertSame([], $this->inspector->decode($value));
	}

	public function testBinaryIsNotText(): void {
		$this->assertSame([], $this->inspector->decode(base64_encode(hash('sha512', 'x', true))));
		// 89 % printable is still binary, 90 % is text.
		$this->assertSame([], $this->inspector->decode(base64_encode(str_repeat('a', 89) . str_repeat("\x01", 11))));
		$this->assertCount(1, $this->inspector->decode(base64_encode(str_repeat('a', 90) . str_repeat("\x01", 10))));
	}

	public function testLowerCaseWordsAreNotBase64Text(): void {
		$this->assertSame([], $this->inspector->decode('contactsinteraction'));
		$this->assertSame([], $this->inspector->decode('integration_openai'));
	}
}
