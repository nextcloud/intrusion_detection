<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Net;

use OCA\IntrusionDetection\Net\FetchMetadata;
use OCP\IRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class FetchMetadataTest extends TestCase {
	/**
	 * @return array<string, array{string, array<string, string>}>
	 */
	public static function lures(): array {
		return [
			'another site sent the browser there' => ['GET', ['Sec-Fetch-Site' => 'cross-site', 'Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'document']],
			'a sibling host of the same site sent the browser there' => ['GET', ['Sec-Fetch-Site' => 'same-site', 'Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'document', 'Referer' => 'https://mail.example.com/inbox']],
			'a sibling host without a referrer' => ['GET', ['Sec-Fetch-Site' => ' Same-Site ', 'Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'document']],
			'an image' => ['GET', ['Sec-Fetch-Site' => 'same-site', 'Sec-Fetch-Mode' => 'no-cors', 'Sec-Fetch-Dest' => 'image']],
			'a script, header case and spaces' => ['GET', ['Sec-Fetch-Dest' => ' Script ']],
			'a frame' => ['GET', ['Sec-Fetch-Site' => 'same-origin', 'Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'iframe']],
			'HEAD' => ['HEAD', ['Sec-Fetch-Dest' => 'image']],
			'an image on another site' => ['GET', ['Sec-Fetch-Dest' => 'image', 'Referer' => 'https://mail.example.org/inbox']],
			'the server on another port' => ['GET', ['Sec-Fetch-Dest' => 'image', 'Referer' => 'https://cloud.example.com:8443/']],
			'an opaque origin' => ['GET', ['Sec-Fetch-Site' => 'cross-site', 'Origin' => 'null']],
		];
	}

	/**
	 * @param array<string, string> $headers
	 */
	#[DataProvider('lures')]
	public function testLures(string $method, array $headers): void {
		$this->assertTrue(FetchMetadata::isLure($this->request($method, $headers)));
	}

	/**
	 * @return array<string, array{string, array<string, string>}>
	 */
	public static function noLures(): array {
		return [
			'a script without fetch metadata' => ['GET', []],
			'the user went there' => ['GET', ['Sec-Fetch-Site' => 'none', 'Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'document']],
			'a script of the same site' => ['GET', ['Sec-Fetch-Site' => 'same-origin', 'Sec-Fetch-Mode' => 'cors', 'Sec-Fetch-Dest' => 'empty']],
			'a POST, which no image or link makes' => ['POST', ['Sec-Fetch-Site' => 'cross-site', 'Sec-Fetch-Mode' => 'no-cors', 'Sec-Fetch-Dest' => 'image']],
			'PROPFIND' => ['PROPFIND', ['Sec-Fetch-Dest' => 'image']],
			'a page of this server as the referrer' => ['GET', ['Sec-Fetch-Site' => 'cross-site', 'Sec-Fetch-Dest' => 'image', 'Referer' => 'https://cloud.example.com/index.php/apps/files']],
			'this server as the origin, in another case' => ['GET', ['Sec-Fetch-Site' => 'cross-site', 'Origin' => 'https://Cloud.Example.com']],
			'a page of this server, same-site' => ['GET', ['Sec-Fetch-Site' => 'same-site', 'Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'document', 'Referer' => 'https://cloud.example.com/index.php/apps/files']],
		];
	}

	/**
	 * @param array<string, string> $headers
	 */
	#[DataProvider('noLures')]
	public function testNoLures(string $method, array $headers): void {
		$this->assertFalse(FetchMetadata::isLure($this->request($method, $headers)));
	}

	/**
	 * @param array<string, string> $headers
	 */
	private function request(string $method, array $headers): IRequest {
		$request = $this->createMock(IRequest::class);
		$request->method('getMethod')->willReturn($method);
		$request->method('getServerHost')->willReturn('cloud.example.com');
		$request->method('getHeader')->willReturnCallback(static fn (string $name): string => $headers[$name] ?? '');
		return $request;
	}
}
