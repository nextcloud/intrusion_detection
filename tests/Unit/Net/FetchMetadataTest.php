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
	/** What a browser sends for a form another site submits by itself */
	private const FORM = [
		'Sec-Fetch-Site' => 'cross-site', 'Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'document',
		'Origin' => 'https://attacker.example.org', 'Content-Type' => 'application/x-www-form-urlencoded',
		'User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0',
	];

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
			'a request another site fetched, by its Origin alone' => ['GET', ['Origin' => 'https://attacker.example.org']],
			'a form another site submits' => ['POST', self::FORM],
			'a form in a frame of a sibling host' => ['POST', ['Sec-Fetch-Site' => 'same-site', 'Sec-Fetch-Dest' => 'iframe', 'Origin' => 'https://mail.example.com', 'Content-Type' => 'Multipart/Form-Data; boundary=x'] + self::FORM],
			'a form from a sandboxed frame' => ['POST', ['Origin' => 'null'] + self::FORM],
			'a form of a browser without fetch metadata' => ['POST', ['Origin' => 'https://attacker.example.org', 'Content-Type' => 'application/x-www-form-urlencoded']],
			'a script that posts text' => ['POST', ['Sec-Fetch-Mode' => 'cors', 'Sec-Fetch-Dest' => 'empty', 'Content-Type' => 'text/plain;charset=UTF-8'] + self::FORM],
			'a beacon without a body' => ['POST', ['Sec-Fetch-Mode' => 'no-cors', 'Sec-Fetch-Dest' => 'empty', 'Content-Type' => ''] + self::FORM],
			'a link ping' => ['POST', ['Sec-Fetch-Mode' => 'no-cors', 'Sec-Fetch-Dest' => 'empty', 'Content-Type' => 'text/ping', 'Origin' => ''] + self::FORM],
			'a report of another site\'s policy' => ['POST', ['Sec-Fetch-Mode' => 'no-cors', 'Sec-Fetch-Dest' => 'report', 'Content-Type' => 'application/csp-report', 'Origin' => ''] + self::FORM],
			'a preflight' => ['OPTIONS', ['Sec-Fetch-Mode' => 'cors', 'Sec-Fetch-Dest' => 'empty', 'Access-Control-Request-Method' => 'PUT', 'Content-Type' => ''] + self::FORM],
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
			'a POST, which no image makes' => ['POST', ['Sec-Fetch-Site' => 'cross-site', 'Sec-Fetch-Mode' => 'no-cors', 'Sec-Fetch-Dest' => 'image']],
			'PROPFIND' => ['PROPFIND', ['Sec-Fetch-Dest' => 'image']],
			'a PUT, which needs a preflight' => ['PUT', self::FORM],
			'DELETE' => ['DELETE', self::FORM],
			'PROPFIND from another site' => ['PROPFIND', self::FORM],
			'JSON, which needs a preflight' => ['POST', ['Content-Type' => 'application/json'] + self::FORM],
			'XML, which needs a preflight' => ['POST', ['Content-Type' => 'application/xml'] + self::FORM],
			'a header only scripts send' => ['POST', ['OCS-APIRequest' => 'true'] + self::FORM],
			'a request token' => ['POST', ['requesttoken' => 'abc'] + self::FORM],
			'X-Requested-With on an image' => ['GET', ['X-Requested-With' => 'XMLHttpRequest', 'Sec-Fetch-Dest' => 'image']],
			'a form posted by an attack tool' => ['POST', ['User-Agent' => 'sqlmap/1.7.2#stable (https://sqlmap.org)'] + self::FORM],
			'an image fetched by curl' => ['GET', ['Sec-Fetch-Site' => 'cross-site', 'Sec-Fetch-Mode' => 'no-cors', 'Sec-Fetch-Dest' => 'image', 'User-Agent' => 'curl/8.4.0']],
			'a form posted to a WebSocket' => ['POST', ['Sec-Fetch-Mode' => 'websocket'] + self::FORM],
			'a form in the same-origin mode' => ['POST', ['Sec-Fetch-Mode' => 'same-origin'] + self::FORM],
			'a form claiming the same origin with a foreign Origin' => ['POST', ['Sec-Fetch-Site' => 'same-origin'] + self::FORM],
			'a form the user started' => ['POST', ['Sec-Fetch-Site' => 'none'] + self::FORM],
			'a form of this server' => ['POST', ['Sec-Fetch-Site' => 'same-origin', 'Origin' => 'https://cloud.example.com'] + self::FORM],
			'a form with this server as referrer' => ['POST', ['Referer' => 'https://cloud.example.com/login'] + self::FORM],
			'a POST without fetch metadata or Origin' => ['POST', ['Content-Type' => 'application/x-www-form-urlencoded']],
			'a POST with an Origin that is no URL' => ['POST', ['Origin' => 'attacker', 'Content-Type' => 'application/x-www-form-urlencoded']],
			'OPTIONS that is no preflight' => ['OPTIONS', ['Sec-Fetch-Mode' => 'cors', 'Sec-Fetch-Dest' => 'empty', 'Content-Type' => ''] + self::FORM],
			'a preflight in the navigate mode' => ['OPTIONS', ['Sec-Fetch-Mode' => 'navigate', 'Access-Control-Request-Method' => 'PUT'] + self::FORM],
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
