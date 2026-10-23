<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Login;

use OCA\IntrusionDetection\Login\LoginClassifier;
use OCA\IntrusionDetection\Login\LoginKind;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Tests\BasicAuthServer;
use OCP\IRequest;
use OCP\IUser;
use OCP\User\Events\UserLoggedInEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class LoginClassifierTest extends TestCase {
	use BasicAuthServer;

	/**
	 * Token login, password, method, path, request headers, Basic credentials in $_SERVER, expected kind.
	 *
	 * @return array<string, array{bool, ?string, string, string, array<string, string>, array{0: ?string, 1: ?string}, LoginKind}>
	 */
	public static function logins(): array {
		$basic = ['alice', 'secret'];
		$none = [null, null];
		return [
			'login form' => [false, 'secret', 'POST', '/login', [], $none, LoginKind::FormPassword],
			'a token login without a token header or Basic credentials' => [true, 'secret', 'POST', '/login', [], $none, LoginKind::RestoredSession],
			'Basic auth with the real password on WebDAV' => [false, 'secret', 'PROPFIND', '/files/alice', ['Authorization' => 'Basic YWxpY2U6c2VjcmV0'], $basic, LoginKind::ClientPassword],
			'Basic auth on the login route' => [false, 'secret', 'POST', '/login', ['Authorization' => 'Basic YWxpY2U6c2VjcmV0'], $basic, LoginKind::ClientPassword],
			'login form with a forged Bearer header' => [false, 'secret', 'POST', '/login', ['Authorization' => 'Bearer x'], $none, LoginKind::FormPassword],
			'login form with forged PHP-Auth-User and PHP-Auth-Pw headers' => [false, 'secret', 'POST', '/login', ['PHP_AUTH_USER' => 'x', 'PHP_AUTH_PW' => 'secret'], $none, LoginKind::FormPassword],
			'login form with Basic credentials for another password' => [false, 'secret', 'POST', '/login', [], ['alice', 'other'], LoginKind::FormPassword],
			'Basic user without a password' => [false, 'secret', 'POST', '/login', [], ['alice', null], LoginKind::FormPassword],
			'passwordless (WebAuthn)' => [false, '', 'POST', '/login', [], $none, LoginKind::Sso],
			'SSO backend without a secret' => [false, null, 'GET', '/apps/user_saml/saml/acs', [], $none, LoginKind::Sso],
			'SSO backend with a stored secret' => [false, 'stored-secret', 'GET', '/apps/user_saml/saml/acs', [], $none, LoginKind::OtherPassword],
			'login page fetched, not submitted' => [false, 'secret', 'GET', '/login', [], $none, LoginKind::OtherPassword],
			'another POST route with a forged header' => [false, 'secret', 'POST', '/login/confirm', ['Authorization' => 'Bearer x'], $none, LoginKind::OtherPassword],
		];
	}

	/**
	 * @param array<string, string> $headers
	 * @param array{0: ?string, 1: ?string} $basic
	 */
	#[DataProvider('logins')]
	public function testHeadersNeverDecideAndUnknownPasswordLoginsCountAsInteractive(bool $tokenLogin, ?string $password, string $method, string $path, array $headers, array $basic, LoginKind $expected): void {
		$this->setBasicCredentials(...$basic);
		$request = $this->createMock(IRequest::class);
		$request->method('getHeader')->willReturnCallback(static fn (string $name): string => $headers[$name] ?? '');
		$request->method('getMethod')->willReturn($method);
		$request->method('getPathInfo')->willReturn($path);

		$event = new UserLoggedInEvent($this->createMock(IUser::class), 'alice', $password, $tokenLogin);
		$this->assertSame($expected, (new LoginClassifier($request, new RequestContext()))->classify($event));
	}

	public function testAnUnreadablePathIsStillAPasswordLogin(): void {
		$request = $this->createMock(IRequest::class);
		$request->method('getMethod')->willReturn('POST');
		$request->method('getPathInfo')->willThrowException(new \Exception('no path'));
		$event = new UserLoggedInEvent($this->createMock(IUser::class), 'alice', 'secret', false);
		$this->assertSame(LoginKind::OtherPassword, (new LoginClassifier($request, new RequestContext()))->classify($event));
	}

	public function testTheAnswerIsKeptForTheLogin(): void {
		$request = $this->createMock(IRequest::class);
		$request->expects($this->once())->method('getMethod')->willReturn('POST');
		$request->method('getPathInfo')->willReturn('/login');
		$classifier = new LoginClassifier($request, new RequestContext());
		$event = new UserLoggedInEvent($this->createMock(IUser::class), 'alice', 'secret', false);
		$this->assertSame(LoginKind::FormPassword, $classifier->classify($event));
		$this->assertSame(LoginKind::FormPassword, $classifier->classify($event));
	}
}
