<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\LoginHistory;

use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\SessionConfirmation;
use OCA\IntrusionDetection\KnownDevice\KnownDevice;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Listener\LoginHistoryListener;
use OCA\IntrusionDetection\Login\InteractiveLogin;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Notification\LoginNotices;
use OCA\IntrusionDetection\Tests\BasicAuthServer;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengePassed;
use OCP\IRequest;
use OCP\IUser;
use OCP\Security\Bruteforce\IThrottler;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * Which kind of login each successful login is, and whether it is
 * recorded at all.
 */
class LoginHistoryListenerTest extends TestCase {
	use BasicAuthServer;

	/** @var array<string, string> */
	private array $headers = [];
	private string $method = 'POST';
	private string $path = '/login';
	private bool $bypass = false;
	/** @var list<array{string, string, bool, bool}> uid, method, known device, browser */
	private array $recorded = [];
	/** @var list<string> */
	private array $noticed = [];
	private int $secondFactors = 0;
	private ?KnownDevice $device = null;
	/** @var list<array{string, string}> */
	private array $proofs = [];

	/**
	 * Request headers, Basic credentials in $_SERVER, method, path, password, token login, expected method, browser.
	 *
	 * @return array<string, array{array<string, string>, ?array{string, string}, string, string, ?string, bool, ?string, bool}>
	 */
	public static function logins(): array {
		return [
			'the login form' => [[], null, 'POST', '/login', 'secret', false, LoginHistory::METHOD_PASSWORD, true],
			'the login form with forged credential headers' => [['Authorization' => 'Bearer x', 'PHP_AUTH_USER' => 'a'], null, 'POST', '/login', 'secret', false, LoginHistory::METHOD_PASSWORD, true],
			'an app with the password' => [['Authorization' => 'Basic YTpi'], ['a', 'secret'], 'PROPFIND', '/files/a', 'secret', false, LoginHistory::METHOD_CLIENT_PASSWORD, false],
			'an app password' => [['Authorization' => 'Basic YTpi'], ['a', 'app-password'], 'PROPFIND', '/files/a', 'app-password', true, LoginHistory::METHOD_APP_PASSWORD, false],
			'a bearer token' => [['Authorization' => 'Bearer abc'], null, 'GET', '/ocs/v2.php/cloud/user', '', true, LoginHistory::METHOD_TOKEN, false],
			'single sign-on' => [[], null, 'GET', '/apps/user_saml/saml/acs', '', false, LoginHistory::METHOD_SSO, true],
			'a password login of another kind' => [[], null, 'GET', '/apps/user_saml/saml/acs', 'stored-secret', false, LoginHistory::METHOD_SSO, true],
			'a session restored from its token' => [[], null, 'GET', '/apps/files', '', true, null, false],
			'a session restored from its token with a forged Basic header' => [['Authorization' => 'Basic YTpi'], null, 'GET', '/apps/files', '', true, null, false],
		];
	}

	/**
	 * @param array<string, string> $headers
	 * @param ?array{string, string} $basic
	 */
	#[DataProvider('logins')]
	public function testEachKindOfLogin(array $headers, ?array $basic, string $method, string $path, string $password, bool $token, ?string $expected, bool $browser): void {
		[$this->headers, $this->method, $this->path] = [$headers, $method, $path];
		if ($basic !== null) {
			$this->setBasicCredentials(...$basic);
		}
		$this->listener()->handle(new UserLoggedInEvent($this->user(), 'alice', $password, $token));
		$this->assertSame($expected === null ? [] : [['alice', $expected, false, $browser]], $this->recorded);
	}

	public function testARememberMeCookieLoginIsRecorded(): void {
		$this->listener()->handle(new UserLoggedInWithCookieEvent($this->user(), 'alice', null));
		$this->assertSame([['alice', LoginHistory::METHOD_COOKIE, false, true]], $this->recorded);
		$this->assertSame([], $this->noticed, 'Not an interactive login');
	}

	public function testAnInteractiveLoginRecognisesItsDeviceAndMayShowTheNotice(): void {
		$this->device = new KnownDevice(3, 'alice', 'firefox', 'linux', 'Firefox on Linux', null, 1, 1);
		$this->listener()->handle(new UserLoggedInEvent($this->user(), 'alice', 'secret', false));
		$this->assertSame([['alice', LoginHistory::METHOD_PASSWORD, true, true]], $this->recorded);
		$this->assertSame(['alice'], $this->noticed);
		$this->assertSame([['alice', IConfirmationMethod::KNOWN_DEVICE]], $this->proofs, 'The session proved the device');
	}

	public function testBypassListedAddressesAreNotRecorded(): void {
		$this->bypass = true;
		$this->listener()->handle(new UserLoggedInEvent($this->user(), 'alice', 'secret', false));
		$this->assertSame([], $this->recorded);
	}

	public function testASecondFactorIsNoted(): void {
		$this->listener()->handle(new TwoFactorProviderChallengePassed($this->user(), $this->createMock(IProvider::class)));
		$this->assertSame(1, $this->secondFactors);
	}

	public function testAFailureNeverBreaksTheLogin(): void {
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willThrowException(new \RuntimeException('database down'));
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error');
		$this->listener($container, $logger)->handle(new UserLoggedInEvent($this->user(), 'alice', 'secret', false));
	}

	private function listener(?ContainerInterface $container = null, ?LoggerInterface $logger = null): LoginHistoryListener {
		$request = $this->createMock(IRequest::class);
		$request->method('getHeader')->willReturnCallback(fn (string $name): string => $this->headers[$name] ?? '');
		$request->method('getMethod')->willReturnCallback(fn (): string => $this->method);
		$request->method('getPathInfo')->willReturnCallback(fn (): string => $this->path);
		$request->method('getRemoteAddress')->willReturn('198.51.100.7');
		$throttler = $this->createMock(IThrottler::class);
		$throttler->method('isBypassListed')->willReturnCallback(fn (): bool => $this->bypass);
		$settings = $this->createMock(Settings::class);
		$settings->method('isEnabled')->willReturn(true);

		$history = $this->createMock(LoginHistory::class);
		$history->method('record')->willReturnCallback(function (string $uid, string $method, $source, $agent, ?KnownDevice $device, bool $browser): int {
			$this->recorded[] = [$uid, $method, $device !== null, $browser];
			return 1;
		});
		$history->method('secondFactorPassed')->willReturnCallback(function (): void {
			$this->secondFactors++;
		});
		$devices = $this->createMock(KnownDevices::class);
		$devices->method('recognise')->willReturnCallback(fn (): ?KnownDevice => $this->device);
		$notices = $this->createMock(LoginNotices::class);
		$notices->method('atLogin')->willReturnCallback(function (string $uid): void {
			$this->noticed[] = $uid;
		});
		$confirmation = $this->createMock(SessionConfirmation::class);
		$confirmation->method('proved')->willReturnCallback(function (string $uid, string $by): void {
			$this->proofs[] = [$uid, $by];
		});
		if ($container === null) {
			$container = $this->createMock(ContainerInterface::class);
			$container->method('get')->willReturnCallback(static fn (string $id): object => match ($id) {
				LoginHistory::class => $history,
				KnownDevices::class => $devices,
				LoginNotices::class => $notices,
				SessionConfirmation::class => $confirmation,
			});
		}
		return new LoginHistoryListener(
			$settings,
			new InteractiveLogin($request),
			new RemoteAddressResolver($request, $throttler),
			$request,
			$container,
			$logger ?? $this->createMock(LoggerInterface::class),
		);
	}

	private function user(): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		return $user;
	}
}
