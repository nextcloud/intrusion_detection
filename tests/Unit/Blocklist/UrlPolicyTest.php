<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Blocklist;

use OCA\IntrusionDetection\Blocklist\UrlPolicy;
use OCP\Security\IRemoteHostValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class UrlPolicyTest extends TestCase {
	/**
	 * @return array<string, array{string, bool}>
	 */
	public static function urls(): array {
		return [
			'https' => ['https://lists.example.org/drop.txt', true],
			'https with port and query' => ['https://lists.example.org:8443/drop.txt?v=1', true],
			'upper-case scheme' => ['HTTPS://lists.example.org/drop.txt', true],
			'http' => ['http://lists.example.org/drop.txt', false],
			'ftp' => ['ftp://lists.example.org/drop.txt', false],
			'file' => ['file:///etc/passwd', false],
			'no scheme' => ['lists.example.org/drop.txt', false],
			'credentials' => ['https://user:secret@lists.example.org/drop.txt', false],
			'user only' => ['https://user@lists.example.org/drop.txt', false],
			'no host' => ['https:///drop.txt', false],
			'space' => ['https://lists.example.org/a b', false],
			'newline' => ["https://lists.example.org/a\nb", false],
			'too long' => ['https://lists.example.org/' . str_repeat('a', 2100), false],
		];
	}

	#[DataProvider('urls')]
	public function testShape(string $url, bool $allowed): void {
		$this->assertSame($allowed, UrlPolicy::hasValidShape($url));
	}

	public function testLocalHostsAreRefusedByCoresValidator(): void {
		$validator = $this->createMock(IRemoteHostValidator::class);
		$validator->method('isValid')->willReturnCallback(static fn (string $host): bool => !in_array($host, ['localhost', '127.0.0.1', '[::1]', '10.0.0.5'], true));
		$policy = new UrlPolicy($validator);
		$this->assertTrue($policy->isAllowed('https://lists.example.org/x'));
		$this->assertFalse($policy->isAllowed('https://localhost/x'));
		$this->assertFalse($policy->isAllowed('https://127.0.0.1/x'));
		$this->assertFalse($policy->isAllowed('https://[::1]/x'));
		$this->assertFalse($policy->isAllowed('https://10.0.0.5/x'));
		$this->assertFalse($policy->isAllowed('http://lists.example.org/x'), 'The shape is checked first');
	}
}
