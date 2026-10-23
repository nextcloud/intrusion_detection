<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Listener;

use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PayloadResponder;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PendingHit;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialUse;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialUseResolver;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\PresentedCredential;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Listener\Login\BreachStep;
use OCA\IntrusionDetection\Listener\Login\CredentialUseStep;
use OCA\IntrusionDetection\Listener\Login\HistoryStep;
use OCA\IntrusionDetection\Listener\Login\ILoginStep;
use OCA\IntrusionDetection\Listener\Login\KnownDeviceStep;
use OCA\IntrusionDetection\Listener\Login\LoginFacts;
use OCA\IntrusionDetection\Listener\Login\NoticeStep;
use OCA\IntrusionDetection\Listener\Login\PasswordChangeStep;
use OCA\IntrusionDetection\Listener\Login\PayloadStep;
use OCA\IntrusionDetection\Listener\Login\RecordStep;
use OCA\IntrusionDetection\Listener\Login\StepUpStep;
use OCA\IntrusionDetection\Listener\LoginListener;
use OCA\IntrusionDetection\Login\LoginGate;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\State\HotState;
use OCA\IntrusionDetection\Tests\LoginSteps;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IRequest;
use OCP\IUser;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class LoginListenerTest extends TestCase {
	private const NOW = 1_792_500_000;

	/** @var list<string> the listeners built, in order */
	private array $built = [];
	private RequestContext $context;
	private AppSettings&MockObject $settings;
	private LoginGate&MockObject $gate;
	private ?bool $first = true;
	private int $sessionsUntil = 0;
	private string $authorization = '';
	/** @var array<string, string> */
	private array $server = [];

	protected function setUp(): void {
		parent::setUp();
		$this->context = new RequestContext();
		$this->settings = $this->createMock(AppSettings::class);
		$this->settings->method('isEnabled')->willReturn(true);
		$this->gate = $this->createMock(LoginGate::class);
		$this->gate->method('isFirst')->willReturnCallback(fn (): ?bool => $this->first);
		$this->server = $_SERVER;
	}

	protected function tearDown(): void {
		$_SERVER = $this->server;
		parent::tearDown();
	}

	private function listener(?ContainerInterface $container = null): LoginListener {
		$addresses = $this->createMock(RemoteAddressResolver::class);
		$addresses->method('current')->willReturn(SourceKey::fromIp('203.0.113.5'));
		$request = $this->createMock(IRequest::class);
		$request->method('getHeader')->willReturnCallback(fn (string $name): string => $name === 'Authorization' ? $this->authorization : '');
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(self::NOW);
		if ($container === null) {
			$container = $this->createMock(ContainerInterface::class);
			$container->method('get')->willReturnCallback(function (string $class): ILoginStep {
				$this->built[] = $class;
				return $this->noStep();
			});
		}
		$hotState = $this->createMock(HotState::class);
		$hotState->method('stepUpSessionsUntil')->willReturnCallback(fn (): int => $this->sessionsUntil);
		return new LoginListener($this->settings, $hotState, $this->context, $this->gate, $time, LoginSteps::withRequest($container, $request, $addresses, $this->context), $this->createMock(LoggerInterface::class));
	}

	private function login(bool $token): UserLoggedInEvent {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		return new UserLoggedInEvent($user, 'alice', $token ? null : 'secret', $token);
	}

	private function appPassword(): void {
		$_SERVER['PHP_AUTH_USER'] = 'alice';
		$_SERVER['PHP_AUTH_PW'] = 'aaaaa-bbbbb-ccccc-ddddd-eeeee';
	}

	public function testARepeatedAppPasswordBuildsNothing(): void {
		$this->appPassword();
		$this->first = false;
		$this->listener()->handle($this->login(true));
		$this->assertSame([], $this->built);
	}

	public function testTheFirstAppPasswordLoginOfTheHourIsRecorded(): void {
		$this->appPassword();
		$this->listener()->handle($this->login(true));
		$this->assertSame([RecordStep::class, HistoryStep::class], $this->built);
	}

	public function testWithoutAMemoryCacheTheRecordsCheckTheDatabase(): void {
		$this->authorization = 'Bearer abc';
		$this->first = null;
		$this->listener()->handle($this->login(true));
		$this->assertSame([RecordStep::class, HistoryStep::class], $this->built);
	}

	public function testAPasswordLoginRunsTheStepUpFirstAndTheNoticeLast(): void {
		$this->listener()->handle($this->login(false));
		$this->assertSame([StepUpStep::class, RecordStep::class, BreachStep::class, PasswordChangeStep::class, KnownDeviceStep::class, HistoryStep::class, NoticeStep::class], $this->built);
	}

	public function testABrowserSessionRestoredFromItsTokenIsNoAppLogin(): void {
		$this->gate->expects($this->never())->method('isFirst');
		$this->listener()->handle($this->login(true));
		$this->assertSame([RecordStep::class, PasswordChangeStep::class], $this->built, 'and no history: a restored session is no new login');
	}

	public function testAReturningSessionRunsTheStepUpWhileUnconfirmedSessionsMayExist(): void {
		$this->sessionsUntil = self::NOW + 60;
		$this->appPassword();
		$this->first = false;
		$this->listener()->handle($this->login(true));
		$this->listener()->handle(new UserLoggedInWithCookieEvent($this->createMock(IUser::class), 'alice', null));
		$this->assertSame([StepUpStep::class, StepUpStep::class, PasswordChangeStep::class, HistoryStep::class], $this->built);
	}

	public function testPendingProbesAndCredentialsGetTheirListeners(): void {
		$this->appPassword();
		$this->first = false;
		$this->context->set(PayloadResponder::CONTEXT_KEY, (new \ReflectionClass(PendingHit::class))->newInstanceWithoutConstructor());
		$use = new CredentialUse(PresentedCredential::SCHEME_BASIC, false);
		$use->unknown = true;
		$this->context->set(CredentialUseResolver::CONTEXT_KEY, $use);
		$this->listener()->handle($this->login(true));
		$this->assertSame([PayloadStep::class, CredentialUseStep::class], $this->built);

		$this->built = [];
		$use->resolved = true;
		$this->context->set(PayloadResponder::CONTEXT_KEY, null);
		$this->listener()->handle($this->login(true));
		$this->assertSame([], $this->built, 'a credential that is known needs nothing');
	}

	public function testNothingRunsWhileProtectionIsOff(): void {
		$settings = $this->createMock(AppSettings::class);
		$settings->method('isEnabled')->willReturn(false);
		$this->settings = $settings;
		$this->listener()->handle($this->login(false));
		$this->assertSame([], $this->built);
	}

	public function testAStepThatFailsDoesNotStopTheOthers(): void {
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(function (string $class): ILoginStep {
			$this->built[] = $class;
			if ($class === RecordStep::class) {
				throw new \RuntimeException('cannot build');
			}
			return $this->noStep();
		});
		$this->appPassword();
		$this->listener($container)->handle($this->login(true));
		$this->assertSame([RecordStep::class, HistoryStep::class], $this->built);
	}

	private function noStep(): ILoginStep {
		return new class implements ILoginStep {
			public static function appliesTo(LoginFacts $facts): bool {
				return true;
			}

			public function handle(LoginFacts $facts): void {
			}
		};
	}
}
