<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Listener\Login;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\LoginConfirmations;
use OCA\IntrusionDetection\KnownDevice\KnownDevice;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Listener\Login\HistoryStep;
use OCA\IntrusionDetection\Listener\Login\ILoginStep;
use OCA\IntrusionDetection\Listener\Login\KnownDeviceStep;
use OCA\IntrusionDetection\Listener\Login\LoginFacts;
use OCA\IntrusionDetection\Listener\Login\NoticeStep;
use OCA\IntrusionDetection\Listener\LoginListener;
use OCA\IntrusionDetection\Login\LoginGate;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Notification\LoginNotices;
use OCA\IntrusionDetection\State\HotState;
use OCA\IntrusionDetection\Tests\BasicAuthServer;
use OCA\IntrusionDetection\Tests\LoginSteps;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IRequest;
use OCP\IUser;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
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
class HistoryStepTest extends TestCase {
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
		$this->device = new KnownDevice('3', 'alice', 'firefox', 'linux', 'Firefox on Linux', null, 1, 1);
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

	public function testAFailingStepDoesNotStopTheOthersNorTheLogin(): void {
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error');
		$this->listener($logger, failing: HistoryStep::class)->handle(new UserLoggedInEvent($this->user(), 'alice', 'secret', false));
		$this->assertSame([], $this->recorded);
		$this->assertSame(['alice'], $this->noticed, 'The notice runs after the history');
	}

	/**
	 * The app's login listener with its real steps; those of the history,
	 * the known device and the notice on mocks, the others doing nothing.
	 *
	 * @param ?class-string<ILoginStep> $failing a step that cannot be built
	 */
	private function listener(?LoggerInterface $logger = null, ?string $failing = null): LoginListener {
		$request = $this->createMock(IRequest::class);
		$request->method('getHeader')->willReturnCallback(fn (string $name): string => $this->headers[$name] ?? '');
		$request->method('getMethod')->willReturnCallback(fn (): string => $this->method);
		$request->method('getPathInfo')->willReturnCallback(fn (): string => $this->path);
		$request->method('getRemoteAddress')->willReturn('198.51.100.7');
		$throttler = $this->createMock(IThrottler::class);
		$throttler->method('isBypassListed')->willReturnCallback(fn (): bool => $this->bypass);
		$settings = $this->createMock(AppSettings::class);
		$settings->method('isEnabled')->willReturn(true);

		$history = $this->createMock(LoginHistory::class);
		$history->method('record')->willReturnCallback(function (string $uid, string $method, $source, $agent, bool $knownDevice, bool $browser): int {
			$this->recorded[] = [$uid, $method, $knownDevice, $browser];
			return 1;
		});
		$devices = $this->createMock(KnownDevices::class);
		$devices->method('recognise')->willReturnCallback(fn (): ?KnownDevice => $this->device);
		$notices = $this->createMock(LoginNotices::class);
		$notices->method('atLogin')->willReturnCallback(function (string $uid): void {
			$this->noticed[] = $uid;
		});
		$confirmation = $this->createMock(LoginConfirmations::class);
		$confirmation->method('proved')->willReturnCallback(function (string $uid, string $by): void {
			$this->proofs[] = [$uid, $by];
		});
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $id): ILoginStep => match ($id) {
			$failing => throw new \RuntimeException('database down'),
			HistoryStep::class => new HistoryStep($history),
			KnownDeviceStep::class => new KnownDeviceStep($devices, $confirmation),
			NoticeStep::class => new NoticeStep($notices),
			default => new class implements ILoginStep {
				public static function appliesTo(LoginFacts $facts): bool {
					return true;
				}

				public function handle(LoginFacts $facts): void {
				}
			},
		});
		$gate = $this->createMock(LoginGate::class);
		$gate->method('isFirst')->willReturn(true);
		$context = new RequestContext();
		return new LoginListener(
			$settings,
			$this->createMock(HotState::class),
			$context,
			$gate,
			Server::get(ITimeFactory::class),
			LoginSteps::withRequest($container, $request, new RemoteAddressResolver($request, $throttler, Server::get(ServerAddresses::class)), $context),
			$logger ?? $this->createMock(LoggerInterface::class),
		);
	}

	private function user(): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		return $user;
	}
}
