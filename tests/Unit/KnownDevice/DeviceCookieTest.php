<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\KnownDevice;

use OCA\IntrusionDetection\KnownDevice\DeviceCookie;
use OCP\IConfig;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\Security\ISecureRandom;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class DeviceCookieTest extends TestCase {
	public function testTheCookieIsHttpOnlyLaxForTheWebRootAndSecureOnHttps(): void {
		$https = $this->cookie(protocol: 'https', webroot: '/nextcloud')->options(1_900_000_000);
		$this->assertSame(['expires' => 1_900_000_000, 'path' => '/nextcloud', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax'], $https);
		$http = $this->cookie(protocol: 'http', webroot: '')->options(5);
		$this->assertFalse($http['secure']);
		$this->assertSame('/', $http['path']);
	}

	public function testTheNameCarriesTheInstanceId(): void {
		$this->assertSame('nc_ids_device_oc1a2b3c', $this->cookie()->name());
	}

	public function testANewIdIs43RandomCharacters(): void {
		$cookie = new DeviceCookie($this->createMock(IRequest::class), $this->config(), $this->createMock(IURLGenerator::class), Server::get(ISecureRandom::class));
		$first = $cookie->newId();
		$this->assertSame(DeviceCookie::ID_LENGTH, strlen($first));
		$this->assertTrue(DeviceCookie::isValid($first));
		$this->assertNotSame($first, $cookie->newId());
	}

	/**
	 * @return array<string, array{?string, ?string}>
	 */
	public static function values(): array {
		$valid = str_repeat('aZ0-_', 8) . 'abc';
		return [
			'valid' => [$valid, $valid],
			'missing' => [null, null],
			'too short' => [substr($valid, 1), null],
			'too long' => [$valid . 'x', null],
			'other characters' => [substr($valid, 1) . '=', null],
			'injection' => [substr($valid, 3) . "\r\nX", null],
		];
	}

	#[DataProvider('values')]
	public function testOnlyWellFormedIdsAreRead(?string $value, ?string $expected): void {
		$this->assertSame($expected, $this->cookie(cookie: $value)->read());
	}

	private function cookie(string $protocol = 'https', string $webroot = '', ?string $cookie = null): DeviceCookie {
		$request = $this->createMock(IRequest::class);
		$request->method('getServerProtocol')->willReturn($protocol);
		$request->method('getCookie')->willReturnCallback(static fn (string $name): ?string => $name === 'nc_ids_device_oc1a2b3c' ? $cookie : null);
		$urlGenerator = $this->createMock(IURLGenerator::class);
		$urlGenerator->method('getWebroot')->willReturn($webroot);
		return new DeviceCookie($request, $this->config(), $urlGenerator, $this->createMock(ISecureRandom::class));
	}

	private function config(): IConfig {
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturnCallback(static fn (string $key, string $default = ''): string => $key === 'instanceid' ? 'oc1a2b3c' : $default);
		return $config;
	}
}
