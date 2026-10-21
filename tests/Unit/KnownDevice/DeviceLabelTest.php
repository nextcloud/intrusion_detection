<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\KnownDevice;

use OCA\IntrusionDetection\KnownDevice\DeviceLabel;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class DeviceLabelTest extends TestCase {
	/**
	 * @return array<string, array{?string, string, string, string}>
	 */
	public static function agents(): array {
		return [
			'firefox linux' => ['Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0', 'firefox', 'linux', 'Firefox on Linux'],
			'chrome windows' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36', 'chrome', 'windows', 'Chrome on Windows'],
			'edge is not chrome' => ['Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0', 'edge', 'windows', 'Edge on Windows'],
			'safari mac' => ['Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15', 'safari', 'macos', 'Safari on macOS'],
			'safari iphone' => ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1', 'safari', 'ios', 'Safari on iOS'],
			'chrome android' => ['Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36', 'chrome', 'android', 'Chrome on Android'],
			'desktop client' => ['Mozilla/5.0 (Linux) mirall/3.14.0 (Nextcloud, ubuntu-6.8 ClientArchitecture: x86_64 OsArchitecture: x86_64)', 'nextcloud_desktop', 'linux', 'Nextcloud desktop client on Linux'],
			'unknown' => ['curl/8.0', 'other', 'other', 'Unknown browser'],
			'none' => [null, 'other', 'other', 'Unknown browser'],
		];
	}

	#[DataProvider('agents')]
	public function testFamiliesAreRecognised(?string $agent, string $family, string $platform, string $english): void {
		$this->assertSame([$family, $platform], DeviceLabel::parse($agent));
		$this->assertSame($english, DeviceLabel::english($family, $platform));
		$this->assertSame($english, DeviceLabel::translated($family, $platform, Server::get(IFactory::class)->get('intrusion_detection', 'en')));
	}

	public function testOnlyTheStartOfAHugeAgentIsLookedAt(): void {
		$this->assertSame(['other', 'other'], DeviceLabel::parse(str_repeat('x', DeviceLabel::MAX_LENGTH) . ' Firefox/131.0 Linux'));
	}
}
