<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Confirm;

use OC\Authentication\TwoFactorAuth\ProviderLoader;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\AccountMethods;
use OCA\IntrusionDetection\Confirm\Administrators;
use OCA\IntrusionDetection\Confirm\ConfirmationPolicy;
use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\Methods\EmailCodeMethod;
use OCA\IntrusionDetection\Confirm\Methods\SecondFactorMethod;
use OCA\IntrusionDetection\Confirm\NoMethodOutcome;
use OCA\IntrusionDetection\Confirm\SecondFactors;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Confirm\UntrustedSecondFactors;
use OCA\IntrusionDetection\Notification\MailReach;
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
		$method = new SecondFactorMethod($challenges, new AccountMethods($this->createMock(MailReach::class), new SecondFactors($registry, $this->createMock(ProviderLoader::class), $this->createMock(UntrustedSecondFactors::class), $this->createMock(LoggerInterface::class))));
		$this->assertTrue($method->isAvailable($user, StepUpPolicy::FlaggedSource));
		$this->assertFalse($method->isAvailable($user, StepUpPolicy::FlaggedSource), 'Backup codes alone, or a disabled provider, are not a second factor');
		$this->assertFalse($method->isAvailable($user, StepUpPolicy::FlaggedSource), 'Two factors enforced without a provider: none yet');

		$state = new StepUpState('u', ConfirmationStatus::Pending, [], 0, 0, methods: [IConfirmationMethod::SECOND_FACTOR, IConfirmationMethod::EMAIL_CODE]);
		$start = $method->begin($user, $state);
		$this->assertSame(IConfirmationMethod::PENDING, $start->outcome, 'The login waits for core\'s challenge');
		$this->assertTrue($start->state->secondFactorRequested);
		$this->assertSame([IConfirmationMethod::SECOND_FACTOR], $start->state->methods, 'No code was sent, so none is offered');

		$secondFactors = new SecondFactors($registry, $this->createMock(ProviderLoader::class), $untrusted, $this->createMock(LoggerInterface::class));
		$withUntrusted = new SecondFactorMethod($challenges, new AccountMethods($this->createMock(MailReach::class), $secondFactors));
		$this->assertTrue($withUntrusted->isAvailable($user, StepUpPolicy::FlaggedSource), 'Another provider counts');
		$this->assertFalse($withUntrusted->isAvailable($user, StepUpPolicy::FlaggedSource), 'One set up from an unconfirmed session does not');
		$this->assertFalse($secondFactors->confirms($user, 'totp'));
		$this->assertTrue($secondFactors->confirms($user, 'webauthn'));

		$appPasswordSession = $this->createMock(IChallengeRequester::class);
		$appPasswordSession->method('isAvailable')->willReturn(false);
		$appPasswordSession->method('requestChallenge')->willThrowException(new \LogicException('no'));
		$noChallenge = new SecondFactorMethod($appPasswordSession, new AccountMethods($this->createMock(MailReach::class), $secondFactors));
		$this->assertFalse($noChallenge->isAvailable($user, StepUpPolicy::FlaggedSource));
		$this->assertSame(IConfirmationMethod::UNAVAILABLE, $noChallenge->begin($user, new StepUpState('u', ConfirmationStatus::Pending, [], 0, 0))->outcome);
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
		$methods = $this->createMock(AccountMethods::class);
		$methods->method('byEmail')->willReturn($available);
		return new EmailCodeMethod($this->createMock(EmailCodes::class), $methods);
	}

	private function policy(IConfirmationMethod ...$methods): ConfirmationPolicy {
		$settings = $this->createMock(AppSettings::class);
		$settings->method('stepUpNoMethod')->willReturnCallback(fn (string $policy): string => $this->outcomes[$policy] ?? StepUpPolicy::from($policy)->defaultOutcome()->value);
		$byClass = [];
		foreach ($methods as $i => $method) {
			$byClass['method' . $i] = $method;
		}
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $id): object => $byClass[$id]);
		$administrators = $this->createMock(Administrators::class);
		$administrators->method('isAdministrator')->willReturn(false);
		return new class(array_keys($byClass), $settings, $container, $this->createMock(LoggerInterface::class), $administrators) extends ConfirmationPolicy {
			/**
			 * @param list<string> $list
			 */
			public function __construct(
				private array $list,
				AppSettings $settings,
				ContainerInterface $container,
				LoggerInterface $logger,
				Administrators $administrators,
			) {
				parent::__construct($settings, $container, $logger, $administrators);
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
