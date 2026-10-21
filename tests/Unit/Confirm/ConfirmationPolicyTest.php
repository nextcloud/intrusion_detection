<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Confirm;

use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\ConfirmationPolicy;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\Methods\EmailCodeMethod;
use OCA\IntrusionDetection\Confirm\Methods\SecondFactorMethod;
use OCA\IntrusionDetection\Confirm\NoMethodOutcome;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Confirm\UntrustedSecondFactors;
use OCP\Authentication\TwoFactorAuth\IChallengeRequester;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\IUser;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * The confirmation methods in their order, and the outcome of the policies
 * when no method is available (concept section 11.5).
 */
class ConfirmationPolicyTest extends TestCase {
	/** @var array<string, string> */
	private array $outcomes = [];

	/**
	 * @return array<string, array{bool, bool, list<string>}>
	 */
	public static function accounts(): array {
		return [
			'second factor and email' => [true, true, ['second_factor', 'email_code']],
			'second factor only' => [true, false, ['second_factor']],
			'email only' => [false, true, ['email_code']],
			'neither' => [false, false, []],
		];
	}

	/**
	 * @param list<string> $expected
	 */
	#[DataProvider('accounts')]
	public function testTheMethodsComeInOrderAndOnlyWhenAvailable(bool $secondFactor, bool $email, array $expected): void {
		$policy = $this->policy($this->secondFactor($secondFactor), $this->email($email));
		$user = $this->createMock(IUser::class);
		foreach (StepUpPolicy::cases() as $reason) {
			$this->assertSame($expected, array_map(static fn (IConfirmationMethod $m): string => $m->id(), $policy->methodsFor($user, $reason)), $reason->value);
		}
		$this->assertSame($expected, array_map(static fn (IConfirmationMethod $m): string => $m->id(), $policy->methodsFor($user, 'flagged_source')));
	}

	public function testAMethodOnePolicyRefusesCannotConfirmALoginWithThatReason(): void {
		$picky = $this->createMock(IConfirmationMethod::class);
		$picky->method('id')->willReturn('picky');
		$picky->method('isAvailable')->willReturnCallback(static fn (IUser $u, StepUpPolicy $p): bool => $p !== StepUpPolicy::SprayedPassword);
		$policy = $this->policy($picky, $this->email(true));
		$user = $this->createMock(IUser::class);
		$this->assertSame(['picky', 'email_code'], $this->ids($policy->methodsForAll($user, [StepUpPolicy::FlaggedSource])));
		$this->assertSame(['email_code'], $this->ids($policy->methodsForAll($user, [StepUpPolicy::FlaggedSource, StepUpPolicy::SprayedPassword])));
	}

	public function testABrokenMethodIsLeftOut(): void {
		$broken = $this->createMock(IConfirmationMethod::class);
		$broken->method('id')->willReturn('broken');
		$broken->method('isAvailable')->willThrowException(new \RuntimeException('down'));
		$policy = $this->policy($broken, $this->email(true));
		$this->assertSame(['email_code'], $this->ids($policy->methodsFor($this->createMock(IUser::class), StepUpPolicy::FlaggedSource)));
		$this->assertNull($policy->method('known_device'));
		$this->assertSame('email_code', $policy->method('email_code')?->id());
	}

	public function testAnAccountCanConfirmInABrowserWhenOneMethodAcceptsEveryReason(): void {
		$device = $this->createMock(IConfirmationMethod::class);
		$device->method('id')->willReturn('known_device');
		$device->method('isAvailable')->willReturn(false);
		$device->method('isAvailableInBrowser')->willReturnCallback(static fn (IUser $u, StepUpPolicy $p): bool => $p !== StepUpPolicy::BreachedPassword);
		$broken = $this->createMock(IConfirmationMethod::class);
		$broken->method('id')->willReturn('broken');
		$broken->method('isAvailableInBrowser')->willThrowException(new \RuntimeException('down'));
		$user = $this->createMock(IUser::class);

		$this->assertTrue($this->policy($broken, $device)->canConfirmInBrowser($user, [StepUpPolicy::ProtectedAccount]), 'A device of the account, not of this request');
		$this->assertFalse($this->policy($broken, $device)->canConfirmInBrowser($user, [StepUpPolicy::ProtectedAccount, StepUpPolicy::BreachedPassword]), 'Every reason must accept the method');
		$this->assertTrue($this->policy($device, $this->email(true))->canConfirmInBrowser($user, [StepUpPolicy::BreachedPassword]));
		$this->assertFalse($this->policy($this->email(false))->canConfirmInBrowser($user, [StepUpPolicy::FlaggedSource]));
	}

	public function testOnlyASecondFactorThatIsSetUpCounts(): void {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('u');
		$challenges = $this->createMock(IChallengeRequester::class);
		$challenges->method('isAvailable')->willReturn(true);
		$challenges->expects($this->once())->method('requestChallenge')->with($user)->willReturn('/challenge');
		$registry = $this->createMock(IRegistry::class);
		$registry->method('getProviderStates')->willReturnOnConsecutiveCalls(['totp' => true], ['backup_codes' => true, 'totp' => false], [], ['totp' => true, 'webauthn' => true], ['totp' => true]);
		$untrusted = $this->createMock(UntrustedSecondFactors::class);
		$untrusted->method('marks')->willReturn(['totp' => 1]);
		$untrusted->method('isTrusted')->willReturnCallback(static fn (string $uid, string $id): bool => $id !== 'totp');
		$method = new SecondFactorMethod($challenges, $registry, $this->createMock(UntrustedSecondFactors::class));
		$this->assertTrue($method->isAvailable($user, StepUpPolicy::FlaggedSource));
		$this->assertFalse($method->isAvailable($user, StepUpPolicy::FlaggedSource), 'Backup codes alone, or a disabled provider, are not a second factor');
		$this->assertFalse($method->isAvailable($user, StepUpPolicy::FlaggedSource), 'Two factors enforced without a provider: none yet');

		$state = new StepUpState('u', StepUpState::PENDING, [], 0, 0, methods: [IConfirmationMethod::SECOND_FACTOR, IConfirmationMethod::EMAIL_CODE]);
		$this->assertSame(IConfirmationMethod::PENDING, $method->begin($user, $state), 'The login waits for core\'s challenge');
		$this->assertTrue($state->secondFactorRequested);
		$this->assertSame([IConfirmationMethod::SECOND_FACTOR], $state->methods, 'No code was sent, so none is offered');

		$withUntrusted = new SecondFactorMethod($challenges, $registry, $untrusted);
		$this->assertTrue($withUntrusted->isAvailable($user, StepUpPolicy::FlaggedSource), 'Another provider counts');
		$this->assertFalse($withUntrusted->isAvailable($user, StepUpPolicy::FlaggedSource), 'One set up from an unconfirmed session does not');
		$this->assertFalse($withUntrusted->confirms($user, 'totp'));
		$this->assertTrue($withUntrusted->confirms($user, 'webauthn'));

		$appPasswordSession = $this->createMock(IChallengeRequester::class);
		$appPasswordSession->method('isAvailable')->willReturn(false);
		$appPasswordSession->method('requestChallenge')->willThrowException(new \LogicException('no'));
		$noChallenge = new SecondFactorMethod($appPasswordSession, $registry, $untrusted);
		$this->assertFalse($noChallenge->isAvailable($user, StepUpPolicy::FlaggedSource));
		$this->assertSame(IConfirmationMethod::UNAVAILABLE, $noChallenge->begin($user, new StepUpState('u', StepUpState::PENDING, [], 0, 0)));
	}

	/**
	 * @return array<string, array{array<string, string>, bool, bool, bool}>
	 */
	public static function outcomes(): array {
		return [
			'defaults: one reason refuses' => [[], true, false, true],
			'breached alone: allow and change' => [['breached_password' => 'allow_force_change'], false, false, true],
			'allow notify' => [['flagged_source' => 'allow_notify'], false, true, false],
			'both allowances' => [['flagged_source' => 'allow_notify', 'breached_password' => 'allow_force_change'], false, true, true],
			'any refusal wins' => [['flagged_source' => 'refuse', 'breached_password' => 'allow_force_change'], true, false, true],
		];
	}

	/**
	 * @param array<string, string> $configured
	 */
	#[DataProvider('outcomes')]
	public function testThePoliciesDecideWhenNoMethodIsAvailable(array $configured, bool $refuse, bool $notify, bool $forceChange): void {
		$this->outcomes = $configured;
		$policies = $configured === [] ? [StepUpPolicy::FlaggedSource, StepUpPolicy::BreachedPassword] : array_map(static fn (string $p): StepUpPolicy => StepUpPolicy::from($p), array_keys($configured));
		$decision = $this->policy()->noMethodDecision($policies);
		$this->assertSame([$refuse, $notify, $forceChange], [$decision->refuse, $decision->notify, $decision->forceChange]);
	}

	public function testAFamiliarPlaceTurnsOnlyARefusedProtectedAccountIntoANotice(): void {
		$asked = 0;
		$familiar = static function () use (&$asked): bool {
			$asked++;
			return true;
		};
		$this->outcomes = ['protected_account' => 'refuse', 'flagged_source' => 'refuse'];
		$decision = $this->policy()->noMethodDecision([StepUpPolicy::ProtectedAccount], $familiar);
		$this->assertSame([false, true], [$decision->refuse, $decision->notify]);
		$this->assertTrue($this->policy()->noMethodDecision([StepUpPolicy::ProtectedAccount, StepUpPolicy::FlaggedSource], $familiar)->refuse, 'Other reasons still refuse');
		$this->assertSame(2, $asked);
		$this->policy()->noMethodDecision([StepUpPolicy::FlaggedSource, StepUpPolicy::BreachedPassword], $familiar);
		$this->assertSame(2, $asked, 'Not asked when it decides nothing');
		$this->assertTrue($this->policy()->noMethodDecision([StepUpPolicy::ProtectedAccount], static fn (): bool => false)->refuse);
	}

	public function testEachNoMethodOutcomeIsReadFromItsSetting(): void {
		foreach (NoMethodOutcome::cases() as $outcome) {
			$this->outcomes = ['protected_account' => $outcome->value];
			$this->assertSame($outcome, $this->policy()->noMethodOutcome(StepUpPolicy::ProtectedAccount));
		}
	}

	private function secondFactor(bool $available): IConfirmationMethod {
		$method = $this->createMock(IConfirmationMethod::class);
		$method->method('id')->willReturn(IConfirmationMethod::SECOND_FACTOR);
		$method->method('isAvailable')->willReturn($available);
		return $method;
	}

	private function email(bool $available): IConfirmationMethod {
		$codes = $this->createMock(EmailCodes::class);
		$codes->method('isAvailable')->willReturn($available);
		return new EmailCodeMethod($codes);
	}

	private function policy(IConfirmationMethod ...$methods): ConfirmationPolicy {
		$settings = $this->createMock(Settings::class);
		$settings->method('global')->willReturnCallback(function (string $name): string {
			foreach (StepUpPolicy::cases() as $p) {
				if ($p->settingKey() === $name) {
					return $this->outcomes[$p->value] ?? $p->defaultOutcome()->value;
				}
			}
			return '';
		});
		$byClass = [];
		foreach ($methods as $i => $method) {
			$byClass['method' . $i] = $method;
		}
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $id): object => $byClass[$id]);
		return new class(array_keys($byClass), $settings, $container, $this->createMock(LoggerInterface::class)) extends ConfirmationPolicy {
			/**
			 * @param list<string> $list
			 */
			public function __construct(
				private array $list,
				Settings $settings,
				ContainerInterface $container,
				LoggerInterface $logger,
			) {
				parent::__construct($settings, $container, $logger);
			}

			protected function classes(): array {
				/** @var list<class-string<IConfirmationMethod>> */
				return $this->list;
			}
		};
	}

	/**
	 * @param list<IConfirmationMethod> $methods
	 * @return list<string>
	 */
	private function ids(array $methods): array {
		return array_map(static fn (IConfirmationMethod $m): string => $m->id(), $methods);
	}
}
