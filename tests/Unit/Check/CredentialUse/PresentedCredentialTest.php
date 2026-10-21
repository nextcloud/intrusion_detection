<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check\CredentialUse;

use OC\AppFramework\Http\Request;
use OCA\IntrusionDetection\Check\CredentialUse\PresentedCredential;
use OCP\IConfig;
use OCP\IRequest;
use OCP\IRequestId;
use Test\TestCase;

class PresentedCredentialTest extends TestCase {
	private const COOKIE = 'oc1234567890';
	private const APP_PASSWORD = 'AbCdE-FgHiJ-KlMnO-PqRsT-UvWxY';

	public function testBasicCredentialsAsPhpParsedThem(): void {
		$credential = $this->credential(['PHP_AUTH_USER' => 'alice', 'PHP_AUTH_PW' => self::APP_PASSWORD]);
		$this->assertNotNull($credential);
		$this->assertSame(PresentedCredential::SCHEME_BASIC, $credential->scheme);
		$this->assertSame('alice', $credential->basicUser);
		$this->assertFalse($credential->hasSessionCookie);
		$this->assertTrue($credential->matches(self::APP_PASSWORD));
		$this->assertFalse($credential->matches('something else'));
		$this->assertFalse($credential->matches(null));
	}

	public function testBasicCredentialsFromTheHeaderOnly(): void {
		$credential = $this->credential(['HTTP_AUTHORIZATION' => 'basic ' . base64_encode('alice:' . self::APP_PASSWORD)]);
		$this->assertSame(PresentedCredential::SCHEME_BASIC, $credential?->scheme);
		$this->assertTrue($credential->matches(self::APP_PASSWORD));
	}

	public function testOnlyThePasswordPartIdentifiesTheCredential(): void {
		$alice = $this->credential(['PHP_AUTH_USER' => 'alice', 'PHP_AUTH_PW' => self::APP_PASSWORD]);
		$aliceUpper = $this->credential(['PHP_AUTH_USER' => ' Alice', 'PHP_AUTH_PW' => self::APP_PASSWORD]);
		$bob = $this->credential(['PHP_AUTH_USER' => 'bob', 'PHP_AUTH_PW' => self::APP_PASSWORD]);
		$bearer = $this->credential(['HTTP_AUTHORIZATION' => 'Bearer ' . self::APP_PASSWORD]);
		$this->assertSame($alice?->keyMaterial(), $bob?->keyMaterial());
		$this->assertSame($alice->keyMaterial(), $bearer?->keyMaterial(), 'An app password is one credential over Basic and Bearer');
		$this->assertNotSame($alice->userTag(), $bob->userTag(), 'The account name only adds a tag');
		$this->assertSame($alice->userTag(), $aliceUpper?->userTag());
		$this->assertSame('', $bearer->userTag());
		$this->assertNotSame($alice->keyMaterial(), $this->credential([], [self::COOKIE => self::APP_PASSWORD])?->keyMaterial(), 'A session id is never mistaken for a password');
	}

	public function testBearerComesFirstAndEmptyCredentialsAreIgnored(): void {
		$this->assertSame(PresentedCredential::SCHEME_BEARER, $this->credential(['HTTP_AUTHORIZATION' => 'Bearer tok', 'PHP_AUTH_USER' => 'a', 'PHP_AUTH_PW' => 'b'])?->scheme);
		$this->assertNull($this->credential(['HTTP_AUTHORIZATION' => 'Bearer   ']));
		$this->assertNull($this->credential(['PHP_AUTH_USER' => 'alice', 'PHP_AUTH_PW' => '']));
		$this->assertNull($this->credential(['PHP_AUTH_USER' => '', 'PHP_AUTH_PW' => 'secret']));
		$this->assertNull($this->credential(['HTTP_AUTHORIZATION' => 'Basic !!not-base64!!']));
		$this->assertNull($this->credential(['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('no-colon')]));
		$this->assertNull($this->credential(['HTTP_AUTHORIZATION' => 'Negotiate abc']));
		$this->assertNull($this->credential([]));
	}

	public function testTheSessionCookieWhenNoHeaderLogsIn(): void {
		$credential = $this->credential([], [self::COOKIE => 'session-id-1']);
		$this->assertSame(PresentedCredential::SCHEME_SESSION, $credential?->scheme);
		$this->assertTrue($credential->hasSessionCookie);
		$this->assertTrue($credential->matches('session-id-1'));
		$this->assertSame(PresentedCredential::SCHEME_SESSION, $this->credential(['HTTP_AUTHORIZATION' => 'Negotiate abc'], [self::COOKIE => 'x'])?->scheme);
		$this->assertNull($this->credential([], ['nc_token' => 'remember-me', 'other' => 'x']), 'Only the cookie named after the instance id');
		$this->assertNull(PresentedCredential::fromRequest($this->request([], [self::COOKIE => 'x']), ''));
	}

	public function testAHeaderNextToTheSessionCookieIsTheCredential(): void {
		$request = $this->request(['PHP_AUTH_USER' => 'alice', 'PHP_AUTH_PW' => self::APP_PASSWORD], [self::COOKIE => 'session-id-1']);
		$credential = PresentedCredential::fromRequest($request, self::COOKIE);
		$this->assertSame(PresentedCredential::SCHEME_BASIC, $credential?->scheme);
		$this->assertTrue($credential->hasSessionCookie);

		$cookie = PresentedCredential::sessionCookieOf($request, self::COOKIE);
		$this->assertSame(PresentedCredential::SCHEME_SESSION, $cookie?->scheme);
		$this->assertTrue($cookie->matches('session-id-1'));
		$this->assertSame($this->credential([], [self::COOKIE => 'session-id-1'])?->keyMaterial(), $cookie->keyMaterial());
		$this->assertNull(PresentedCredential::sessionCookieOf($this->request([], []), self::COOKIE));
	}

	public function testTheSecretIsNotShownWhenDumped(): void {
		$credential = $this->credential(['PHP_AUTH_USER' => 'alice', 'PHP_AUTH_PW' => self::APP_PASSWORD]);
		$this->assertStringNotContainsString(self::APP_PASSWORD, print_r($credential, true));
		ob_start();
		var_dump($credential);
		$this->assertStringNotContainsString(self::APP_PASSWORD, (string)ob_get_clean());
	}

	private function credential(array $server, array $cookies = []): ?PresentedCredential {
		return PresentedCredential::fromRequest($this->request($server, $cookies), self::COOKIE);
	}

	private function request(array $server, array $cookies): IRequest {
		return new Request(['server' => $server, 'cookies' => $cookies], $this->createMock(IRequestId::class), $this->createMock(IConfig::class));
	}
}
