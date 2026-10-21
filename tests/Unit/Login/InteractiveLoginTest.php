<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Login;

use OCA\IntrusionDetection\Login\InteractiveLogin;
use OCA\IntrusionDetection\Tests\BasicAuthServer;
use OCP\IRequest;
use OCP\IUser;
use OCP\User\Events\UserLoggedInEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class InteractiveLoginTest extends TestCase {
	use BasicAuthServer;

	/**
	 * Token login, password, method, path, request headers, Basic credentials in $_SERVER, expected kind.
	 *
	 * @return array<string, array{bool, ?string, string, string, array<string, string>, array{0: ?string, 1: ?string}, ?string}>
	 */
	public static function logins(): array {
		$basic = ['alice', 'secret'];
		$none = [null, null];
		return [
			'login form' => [false, 'secret', 'POST', '/login', [], $none, InteractiveLogin::FORM],
			'app password or token (Basic or Bearer)' => [true, 'secret', 'POST', '/login', [], $none, null],
			'Basic auth with the real password on WebDAV' => [false, 'secret', 'PROPFIND', '/files/alice', ['Authorization' => 'Basic YWxpY2U6c2VjcmV0'], $basic, InteractiveLogin::CLIENT],
			'Basic auth on the login route' => [false, 'secret', 'POST', '/login', ['Authorization' => 'Basic YWxpY2U6c2VjcmV0'], $basic, InteractiveLogin::CLIENT],
			'login form with a forged Bearer header' => [false, 'secret', 'POST', '/login', ['Authorization' => 'Bearer x'], $none, InteractiveLogin::FORM],
			'login form with forged PHP-Auth-User and PHP-Auth-Pw headers' => [false, 'secret', 'POST', '/login', ['PHP_AUTH_USER' => 'x', 'PHP_AUTH_PW' => 'secret'], $none, InteractiveLogin::FORM],
			'login form with Basic credentials for another password' => [false, 'secret', 'POST', '/login', [], ['alice', 'other'], InteractiveLogin::FORM],
			'Basic user without a password' => [false, 'secret', 'POST', '/login', [], ['alice', null], InteractiveLogin::FORM],
			'passwordless (WebAuthn)' => [false, '', 'POST', '/login', [], $none, null],
			'SSO backend without a secret' => [false, null, 'GET', '/apps/user_saml/saml/acs', [], $none, null],
			'SSO backend with a stored secret' => [false, 'stored-secret', 'GET', '/apps/user_saml/saml/acs', [], $none, InteractiveLogin::OTHER],
			'login page fetched, not submitted' => [false, 'secret', 'GET', '/login', [], $none, InteractiveLogin::OTHER],
			'another POST route with a forged header' => [false, 'secret', 'POST', '/login/confirm', ['Authorization' => 'Bearer x'], $none, InteractiveLogin::OTHER],
		];
	}

	/**
	 * @param array<string, string> $headers
	 * @param array{0: ?string, 1: ?string} $basic
	 */
	#[DataProvider('logins')]
	public function testHeadersNeverDecideAndUnknownPasswordLoginsCountAsInteractive(bool $tokenLogin, ?string $password, string $method, string $path, array $headers, array $basic, ?string $expected): void {
		$this->setBasicCredentials(...$basic);
		$request = $this->createMock(IRequest::class);
		$request->method('getHeader')->willReturnCallback(static fn (string $name): string => $headers[$name] ?? '');
		$request->method('getMethod')->willReturn($method);
		$request->method('getPathInfo')->willReturn($path);

		$event = new UserLoggedInEvent($this->createMock(IUser::class), 'alice', $password, $tokenLogin);
		$login = new InteractiveLogin($request);
		$this->assertSame($expected, $login->kind($event));
		$this->assertSame($expected === InteractiveLogin::FORM || $expected === InteractiveLogin::OTHER, $login->isPasswordLogin($event));
	}

	public function testAnUnreadablePathIsStillAPasswordLogin(): void {
		$request = $this->createMock(IRequest::class);
		$request->method('getMethod')->willReturn('POST');
		$request->method('getPathInfo')->willThrowException(new \Exception('no path'));
		$event = new UserLoggedInEvent($this->createMock(IUser::class), 'alice', 'secret', false);
		$this->assertSame(InteractiveLogin::OTHER, (new InteractiveLogin($request))->kind($event));
	}

	public function testBasicCredentialsComeFromServerOnly(): void {
		$this->assertFalse(InteractiveLogin::hasBasicCredentials());
		$this->setBasicCredentials('alice', null);
		$this->assertFalse(InteractiveLogin::hasBasicCredentials(), 'No password');
		$this->setBasicCredentials('alice', 'secret');
		$this->assertTrue(InteractiveLogin::hasBasicCredentials());
	}
}
