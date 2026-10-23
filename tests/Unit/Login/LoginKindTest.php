<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Login;

use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\PresentedCredential;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Listener\BreachedPasswordListener;
use OCA\IntrusionDetection\Listener\LoginHistoryListener;
use OCA\IntrusionDetection\Listener\LoginListener;
use OCA\IntrusionDetection\Listener\LoginRecordListener;
use OCA\IntrusionDetection\Listener\PasswordChangeLoginListener;
use OCA\IntrusionDetection\Listener\StepUpLoginListener;
use OCA\IntrusionDetection\Login\LoginClassifier;
use OCA\IntrusionDetection\Login\LoginGate;
use OCA\IntrusionDetection\Login\LoginKind;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\State\HotState;
use OCA\IntrusionDetection\Tests\BasicAuthServer;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUser;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * How each kind of login is told apart, and what follows from it: which
 * login steps run, the login history's method, the forced password
 * change's mode, whether a password login counts as typed, and the
 * credential the request presented.
 *
 * Core's own token login takes a Bearer token case-sensitively, so a
 * lowercase "bearer" header did not log the request in with a token.
 */
class LoginKindTest extends TestCase {
	use BasicAuthServer;

	private const NOW = 1_792_500_000;
	private const COOKIE = 'ocinstance';

	/** @var array<string, string> */
	private array $headers = [];
	/** @var array<string, string> */
	private array $cookies = [];
	private string $method = 'POST';
	private string $path = '/login';
	private int $sessionsUntil = 0;

	/**
	 * The login, the request, and what follows from it.
	 *
	 * @return iterable<string, array{0: array{event: string, password?: ?string, method?: string, path?: string, authorization?: string, basic?: array{string, string}, cookie?: bool}, 1: array{kind: string, steps: list<string>, history: array{?string, bool}, passwordChange: ?string, interactive: ?string, presented: ?string}}>
	 */
	public static function logins(): iterable {
		$browser = ['stepUp', 'record', 'breach', 'passwordChange', 'history'];
		yield 'login form' => [
			['event' => 'login', 'password' => 'secret'],
			['kind' => 'form_password', 'steps' => $browser, 'history' => ['password', true], 'passwordChange' => 'redirect', 'interactive' => 'form', 'presented' => null],
		];
		yield 'Basic auth with the password' => [
			['event' => 'login', 'password' => 'secret', 'method' => 'PROPFIND', 'path' => '/files/alice', 'authorization' => 'Basic YWxpY2U6c2VjcmV0', 'basic' => ['alice', 'secret']],
			['kind' => 'client_password', 'steps' => $browser, 'history' => ['client_password', false], 'passwordChange' => 'refuse', 'interactive' => 'client', 'presented' => 'basic'],
		];
		yield 'login form with Basic credentials for another password' => [
			['event' => 'login', 'password' => 'secret', 'basic' => ['alice', 'other']],
			['kind' => 'form_password', 'steps' => $browser, 'history' => ['password', true], 'passwordChange' => 'redirect', 'interactive' => 'form', 'presented' => 'basic'],
		];
		yield 'login form with a forged Bearer header' => [
			['event' => 'login', 'password' => 'secret', 'authorization' => 'Bearer forged'],
			['kind' => 'form_password', 'steps' => $browser, 'history' => ['password', true], 'passwordChange' => 'redirect', 'interactive' => 'form', 'presented' => 'bearer'],
		];
		yield 'another password login (SSO with a stored secret)' => [
			['event' => 'login', 'password' => 'stored-secret', 'method' => 'GET', 'path' => '/apps/user_saml/saml/acs'],
			['kind' => 'other_password', 'steps' => $browser, 'history' => ['sso', true], 'passwordChange' => 'redirect', 'interactive' => 'other', 'presented' => null],
		];
		yield 'passwordless (SSO)' => [
			['event' => 'login', 'password' => null, 'method' => 'GET', 'path' => '/apps/user_saml/saml/acs'],
			['kind' => 'sso', 'steps' => $browser, 'history' => ['sso', true], 'passwordChange' => 'redirect', 'interactive' => null, 'presented' => null],
		];
		yield 'passwordless with an empty password (WebAuthn)' => [
			['event' => 'login', 'password' => ''],
			['kind' => 'sso', 'steps' => $browser, 'history' => ['sso', true], 'passwordChange' => 'redirect', 'interactive' => null, 'presented' => null],
		];
		yield 'app password over Basic auth' => [
			['event' => 'token', 'method' => 'PROPFIND', 'path' => '/files/alice', 'authorization' => 'Basic YWxpY2U6YXBw', 'basic' => ['alice', 'app']],
			['kind' => 'app_password_basic', 'steps' => ['record', 'history'], 'history' => ['app_password', false], 'passwordChange' => null, 'interactive' => null, 'presented' => 'basic'],
		];
		yield 'Bearer token' => [
			['event' => 'token', 'method' => 'GET', 'path' => '/cloud/user', 'authorization' => 'Bearer token'],
			['kind' => 'bearer', 'steps' => ['record', 'history'], 'history' => ['token', false], 'passwordChange' => null, 'interactive' => null, 'presented' => 'bearer'],
		];
		yield 'Bearer token with Basic credentials too' => [
			['event' => 'token', 'method' => 'GET', 'path' => '/cloud/user', 'authorization' => 'Bearer token', 'basic' => ['alice', 'app']],
			['kind' => 'bearer', 'steps' => ['record', 'history'], 'history' => ['token', false], 'passwordChange' => null, 'interactive' => null, 'presented' => 'bearer'],
		];
		yield 'lowercase bearer: core restored the session from its cookie' => [
			['event' => 'token', 'method' => 'GET', 'path' => '/apps/files/', 'authorization' => 'bearer token', 'cookie' => true],
			['kind' => 'restored_session', 'steps' => ['record', 'passwordChange', 'history'], 'history' => [null, false], 'passwordChange' => 'redirect', 'interactive' => null, 'presented' => 'bearer'],
		];
		yield 'browser session restored from its token' => [
			['event' => 'token', 'method' => 'GET', 'path' => '/apps/files/', 'cookie' => true],
			['kind' => 'restored_session', 'steps' => ['record', 'passwordChange', 'history'], 'history' => [null, false], 'passwordChange' => 'redirect', 'interactive' => null, 'presented' => 'session'],
		];
		yield 'a Basic header PHP did not pass on' => [
			['event' => 'token', 'method' => 'GET', 'path' => '/apps/files/', 'authorization' => 'Basic YWxpY2U6YXBw'],
			['kind' => 'restored_session', 'steps' => ['record', 'passwordChange', 'history'], 'history' => [null, false], 'passwordChange' => 'redirect', 'interactive' => null, 'presented' => 'basic'],
		];
		yield 'remember-me cookie' => [
			['event' => 'cookie', 'method' => 'GET', 'path' => '/apps/files/', 'cookie' => true],
			['kind' => 'remember_me_cookie', 'steps' => ['passwordChange', 'history'], 'history' => ['cookie', true], 'passwordChange' => 'redirect', 'interactive' => null, 'presented' => 'session'],
		];
		yield 'remember-me cookie with Basic credentials' => [
			['event' => 'cookie', 'method' => 'GET', 'path' => '/apps/files/', 'authorization' => 'Basic YWxpY2U6YXBw', 'basic' => ['alice', 'app'], 'cookie' => true],
			['kind' => 'remember_me_cookie', 'steps' => ['passwordChange', 'history'], 'history' => ['cookie', true], 'passwordChange' => 'redirect', 'interactive' => null, 'presented' => 'basic'],
		];
	}

	/**
	 * @param array{event: string, password?: ?string, method?: string, path?: string, authorization?: string, basic?: array{string, string}, cookie?: bool} $login
	 * @param array{kind: string, steps: list<string>, history: array{?string, bool}, passwordChange: ?string, interactive: ?string, presented: ?string} $expected
	 */
	#[DataProvider('logins')]
	public function testEachKindOfLogin(array $login, array $expected): void {
		$event = $this->prepare($login);
		$kind = $this->classifier()->classify($event);
		$this->assertSame($expected, [
			'kind' => $kind->value,
			'steps' => $this->steps($event),
			'history' => $this->historyMethod($event),
			'passwordChange' => $this->passwordChangeMode($event),
			'interactive' => match ($kind) {
				LoginKind::FormPassword => 'form',
				LoginKind::ClientPassword => 'client',
				LoginKind::OtherPassword => 'other',
				default => null,
			},
			'presented' => PresentedCredential::fromRequest($this->request(), self::COOKIE)?->scheme,
		]);
	}

	/**
	 * While unconfirmed sessions may exist, a session that comes back is
	 * checked first; a new password login always is.
	 *
	 * @return iterable<string, array{0: array{event: string, password?: ?string, method?: string, path?: string, authorization?: string, basic?: array{string, string}, cookie?: bool}, 1: list<string>}>
	 */
	public static function returningSessions(): iterable {
		yield 'login form' => [['event' => 'login', 'password' => 'secret'], ['stepUp', 'record', 'breach', 'passwordChange', 'history']];
		yield 'app password over Basic auth' => [['event' => 'token', 'method' => 'PROPFIND', 'authorization' => 'Basic YWxpY2U6YXBw', 'basic' => ['alice', 'app']], ['stepUp', 'record', 'history']];
		yield 'Bearer token' => [['event' => 'token', 'method' => 'GET', 'authorization' => 'Bearer token'], ['stepUp', 'record', 'history']];
		yield 'browser session restored from its token' => [['event' => 'token', 'method' => 'GET', 'cookie' => true], ['stepUp', 'record', 'passwordChange', 'history']];
		yield 'remember-me cookie' => [['event' => 'cookie', 'method' => 'GET', 'cookie' => true], ['stepUp', 'passwordChange', 'history']];
	}

	/**
	 * @param array{event: string, password?: ?string, method?: string, path?: string, authorization?: string, basic?: array{string, string}, cookie?: bool} $login
	 * @param list<string> $expected
	 */
	#[DataProvider('returningSessions')]
	public function testWhileUnconfirmedSessionsMayExistReturningSessionsAreCheckedFirst(array $login, array $expected): void {
		$this->sessionsUntil = self::NOW + 60;
		$this->assertSame($expected, $this->steps($this->prepare($login)));
	}

	/**
	 * @param array{event: string, password?: ?string, method?: string, path?: string, authorization?: string, basic?: array{string, string}, cookie?: bool} $login
	 */
	private function prepare(array $login): UserLoggedInEvent|UserLoggedInWithCookieEvent {
		$this->method = $login['method'] ?? 'POST';
		$this->path = $login['path'] ?? '/login';
		$this->headers = isset($login['authorization']) ? ['Authorization' => $login['authorization']] : [];
		$this->cookies = ($login['cookie'] ?? false) ? [self::COOKIE => 'session-id'] : [];
		$this->setBasicCredentials(...($login['basic'] ?? [null, null]));
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$user->method('canChangePassword')->willReturn(true);
		return match ($login['event']) {
			'login' => new UserLoggedInEvent($user, 'alice', $login['password'] ?? null, false),
			'token' => new UserLoggedInEvent($user, 'alice', 'app', true),
			default => new UserLoggedInWithCookieEvent($user, 'alice', null),
		};
	}

	private function request(): IRequest {
		$request = $this->createMock(IRequest::class);
		$request->method('getHeader')->willReturnCallback(fn (string $name): string => $this->headers[$name] ?? '');
		$request->method('getCookie')->willReturnCallback(fn (string $name): ?string => $this->cookies[$name] ?? null);
		$request->method('getMethod')->willReturnCallback(fn (): string => $this->method);
		$request->method('getPathInfo')->willReturnCallback(fn (): string => $this->path);
		return $request;
	}

	/**
	 * The login steps that run, by name.
	 *
	 * @return list<string>
	 */
	private function steps(UserLoggedInEvent|UserLoggedInWithCookieEvent $event): array {
		$names = [
			StepUpLoginListener::class => 'stepUp',
			LoginRecordListener::class => 'record',
			BreachedPasswordListener::class => 'breach',
			PasswordChangeLoginListener::class => 'passwordChange',
			LoginHistoryListener::class => 'history',
		];
		$built = [];
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(function (string $class) use (&$built, $names): IEventListener {
			$built[] = $names[$class] ?? $class;
			return new class implements IEventListener {
				public function handle(Event $event): void {
				}
			};
		});
		$addresses = $this->createMock(RemoteAddressResolver::class);
		$addresses->method('current')->willReturn(SourceKey::fromIp('203.0.113.5'));
		$gate = $this->createMock(LoginGate::class);
		$gate->method('isFirst')->willReturn(true);
		$hotState = $this->createMock(HotState::class);
		$hotState->method('stepUpSessionsUntil')->willReturnCallback(fn (): int => $this->sessionsUntil);
		(new LoginListener($this->settings(), $hotState, new RequestContext(), $addresses, $gate, $this->classifier(), $this->time(), $container, $this->createMock(LoggerInterface::class)))->handle($event);
		return $built;
	}

	/**
	 * The method and browser flag the login history records, or null when no row is written.
	 *
	 * @return array{?string, bool}
	 */
	private function historyMethod(UserLoggedInEvent|UserLoggedInWithCookieEvent $event): array {
		$recorded = [null, false];
		$history = $this->createMock(LoginHistory::class);
		$history->method('record')->willReturnCallback(function (string $uid, string $method, ?SourceKey $source, ?string $userAgent, mixed $device, bool $browser) use (&$recorded): ?int {
			$recorded = [$method, $browser];
			return 1;
		});
		$addresses = $this->createMock(RemoteAddressResolver::class);
		$addresses->method('current')->willReturn(SourceKey::fromIp('203.0.113.5'));
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(fn (string $class): object => match ($class) {
			LoginHistory::class => $history,
			default => $this->createMock($class),
		});
		(new LoginHistoryListener($this->settings(), $this->classifier(), $addresses, $this->request(), $container, $this->createMock(LoggerInterface::class)))->handle($event);
		return $recorded;
	}

	private function passwordChangeMode(UserLoggedInEvent|UserLoggedInWithCookieEvent $event): ?string {
		$passwords = $this->createMock(PasswordChangeService::class);
		$passwords->method('requiredSince')->willReturn(self::NOW - 60);
		$stored = [];
		$session = $this->createMock(ISession::class);
		$session->method('get')->willReturnCallback(static function (string $key) use (&$stored): mixed {
			return $stored[$key] ?? null;
		});
		$session->method('set')->willReturnCallback(static function (string $key, mixed $value) use (&$stored): void {
			$stored[$key] = $value;
		});
		$state = new SessionState($session, $this->createMock(LoggerInterface::class));
		(new PasswordChangeLoginListener($this->settings(), $passwords, $state, $this->classifier(), $this->createMock(LoggerInterface::class)))->handle($event);
		$marker = $state->get(SessionState::PASSWORD_CHANGE);
		return is_string($marker['mode'] ?? null) ? $marker['mode'] : null;
	}

	private function classifier(): LoginClassifier {
		return new LoginClassifier($this->request(), new RequestContext());
	}

	private function settings(): AppSettings {
		$settings = $this->createMock(AppSettings::class);
		$settings->method('isEnabled')->willReturn(true);
		return $settings;
	}

	private function time(): ITimeFactory {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(self::NOW);
		return $time;
	}
}
