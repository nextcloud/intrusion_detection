<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Http;

use OCA\IntrusionDetection\Http\LocalRedirect;
use OCP\IURLGenerator;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

/**
 * The verify and password pages continue only to local paths: no open
 * redirect through a crafted link.
 */
class LocalRedirectTest extends TestCase {
	/**
	 * @return array<string, array{string}>
	 */
	public static function unsafe(): array {
		return [
			'empty' => [''],
			'another host' => ['https://evil.example/'],
			'protocol-relative' => ['//evil.example/'],
			'scheme without slashes' => ['javascript:alert(1)'],
			'backslash' => ['/\\evil.example'],
			'tab' => ["/\t/evil.example"],
			'newline' => ["/apps/files/\r\nLocation: https://evil.example/"],
			'relative' => ['apps/files'],
			'too long' => ['/' . str_repeat('a', 2000)],
			'the page itself' => ['/index.php/apps/intrusion_detection/verify?redirect_url=/x'],
		];
	}

	#[DataProvider('unsafe')]
	public function testOnlyLocalPathsAreContinuedTo(string $url): void {
		$this->assertFalse(LocalRedirect::isSafe($url, ['/apps/intrusion_detection/verify']));
		$this->assertSame('https://cloud.example/apps/dashboard/', $this->redirect()->target($url, ['/apps/intrusion_detection/verify']));
	}

	public function testALocalPathIsContinuedToOnThisServer(): void {
		$this->assertTrue(LocalRedirect::isSafe('/index.php/apps/files/?dir=/Photos&x=%2F%2Fevil'));
		$this->assertSame('https://cloud.example/index.php/apps/files/?dir=/Photos', $this->redirect()->target('/index.php/apps/files/?dir=/Photos'));
	}

	private function redirect(): LocalRedirect {
		$urls = $this->createMock(IURLGenerator::class);
		$urls->method('getAbsoluteURL')->willReturnCallback(static fn (string $url): string => 'https://cloud.example' . $url);
		$urls->method('linkToDefaultPageUrl')->willReturn('https://cloud.example/apps/dashboard/');
		return new LocalRedirect($urls);
	}
}
