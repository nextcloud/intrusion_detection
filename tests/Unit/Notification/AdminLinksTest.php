<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Notification;

use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\IURLGenerator;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class AdminLinksTest extends TestCase {
	/**
	 * @return array<string, array{string, string, string}>
	 */
	public static function routes(): array {
		return [
			'route known' => ['/index.php/settings/admin/intrusion_detection', '/index.php', 'https://cloud.example.com/index.php/settings/admin/intrusion_detection#detection-42'],
			'route not loaded yet' => ['', '/index.php', 'https://cloud.example.com/index.php/settings/admin/intrusion_detection#detection-42'],
			'route not loaded yet, pretty URLs' => ['', '/', 'https://cloud.example.com/settings/admin/intrusion_detection#detection-42'],
		];
	}

	#[DataProvider('routes')]
	public function testTheLinkWorksAlsoBeforeTheRoutesAreLoaded(string $route, string $index, string $expected): void {
		$urls = $this->createMock(IURLGenerator::class);
		$urls->method('linkToRoute')->with('settings.AdminSettings.index', ['section' => 'intrusion_detection'])->willReturn($route);
		$urls->method('linkTo')->with('', 'index.php')->willReturn($index);
		$urls->method('getAbsoluteURL')->willReturnCallback(static fn (string $path): string => 'https://cloud.example.com' . $path);
		$this->assertSame($expected, (new AdminLinks($urls))->detection(42));
	}
}
