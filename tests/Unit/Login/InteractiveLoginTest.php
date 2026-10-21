<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Login;

use OCA\IntrusionDetection\Login\InteractiveLogin;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUser;
use OCP\User\Events\UserLoggedInEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class InteractiveLoginTest extends TestCase {
	/**
	 * Token login, password, method, path, headers, app password in the session, expected.
	 *
	 * @return array<string, array{bool, ?string, string, string, array<string, string>, bool, bool}>
	 */
	public static function logins(): array {
		return [
			'login form' => [false, 'secret', 'POST', '/login', [], false, true],
			'app password or token (Basic or Bearer)' => [true, 'secret', 'POST', '/login', [], false, false],
			'Basic auth with the real password on WebDAV' => [false, 'secret', 'PROPFIND', '/files/alice', ['Authorization' => 'Basic YWxpY2U6c2VjcmV0'], false, false],
			'Basic auth with the real password, as mod_php passes it' => [false, 'secret', 'GET', '/cloud/user', ['PHP_AUTH_USER' => 'alice'], false, false],
			'Basic auth on the login route' => [false, 'secret', 'POST', '/login', ['Authorization' => 'Basic YWxpY2U6c2VjcmV0'], false, false],
			'app password session' => [false, 'secret', 'POST', '/login', [], true, false],
			'passwordless (WebAuthn)' => [false, '', 'POST', '/login', [], false, false],
			'SSO backend without a secret' => [false, null, 'GET', '/apps/user_saml/saml/acs', [], false, false],
			'SSO backend with a stored secret' => [false, 'stored-secret', 'GET', '/apps/user_saml/saml/acs', [], false, false],
			'login page fetched, not submitted' => [false, 'secret', 'GET', '/login', [], false, false],
			'another POST route' => [false, 'secret', 'POST', '/login/confirm', [], false, false],
		];
	}

	/**
	 * @param array<string, string> $headers
	 */
	#[DataProvider('logins')]
	public function testOnlyTheLoginFormCountsAsInteractive(bool $tokenLogin, ?string $password, string $method, string $path, array $headers, bool $appPasswordSession, bool $expected): void {
		$request = $this->createMock(IRequest::class);
		$request->method('getHeader')->willReturnCallback(static fn (string $name): string => $headers[$name] ?? '');
		$request->method('getMethod')->willReturn($method);
		$request->method('getPathInfo')->willReturn($path);
		$session = $this->createMock(ISession::class);
		$session->method('exists')->willReturnCallback(static fn (string $key): bool => $key === 'app_password' && $appPasswordSession);

		$event = new UserLoggedInEvent($this->createMock(IUser::class), 'alice', $password, $tokenLogin);
		$this->assertSame($expected, (new InteractiveLogin($request, $session))->isPasswordLogin($event));
	}

	public function testAnUnreadablePathIsNotInteractive(): void {
		$request = $this->createMock(IRequest::class);
		$request->method('getHeader')->willReturn('');
		$request->method('getMethod')->willReturn('POST');
		$request->method('getPathInfo')->willThrowException(new \Exception('no path'));
		$event = new UserLoggedInEvent($this->createMock(IUser::class), 'alice', 'secret', false);
		$this->assertFalse((new InteractiveLogin($request, $this->createMock(ISession::class)))->isPasswordLogin($event));
	}
}
