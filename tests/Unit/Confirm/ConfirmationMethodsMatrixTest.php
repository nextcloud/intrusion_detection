<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Confirm;

use OC\Authentication\TwoFactorAuth\ProviderLoader;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\AccountMethods;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\Confirm\ConfirmationPolicy;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\LoginConfirmationStore;
use OCA\IntrusionDetection\Confirm\Methods\AdminApprovalMethod;
use OCA\IntrusionDetection\Confirm\Methods\EmailCodeMethod;
use OCA\IntrusionDetection\Confirm\Methods\KnownDeviceMethod;
use OCA\IntrusionDetection\Confirm\Methods\SecondFactorMethod;
use OCA\IntrusionDetection\Confirm\SecondFactors;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\UntrustedSecondFactors;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\KnownDevice\KnownDevice;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Notification\MailReach;
use OCA\IntrusionDetection\Notification\Mails;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\State\AppState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\TwoFactorAuth\IChallengeRequester;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\Config\IUserConfig;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Mail\IEmailValidator;
use OCP\Security\IHasher;
use OCP\Security\ISecureRandom;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * What an account can confirm a login with, per reason: the methods a
 * login starts in order, whether the account could confirm in a browser
 * (which decides whether its apps are refused), and what the coverage
 * report counts.
 */
class ConfirmationMethodsMatrixTest extends TestCase {
	/** @var array{secondFactor?: bool, untrusted?: bool, backupOnly?: bool, email?: string, mailOff?: bool, deviceHere?: bool, deviceElsewhere?: bool, approvers?: bool} */
	private array $account = [];

	/**
	 * The account, and what each reason gets: the methods, in order, and
	 * whether a browser could confirm. Reasons a known device accepts by
	 * default are flagged_source, protected_account, risky_network and
	 * risk_high; it never accepts sprayed_password, breached_password or
	 * admin_outside_networks.
	 *
	 * @return iterable<string, array{0: array<string, bool|string>, 1: array<string, array{list<string>, bool}>, 2: array{bool, bool, bool}}>
	 */
	public static function accounts(): iterable {
		$none = [[], false];
		$all = static fn (array $answer): array => array_fill_keys(array_map(static fn (StepUpPolicy $p): string => $p->value, StepUpPolicy::cases()), $answer);
		$device = static fn (array $accepted, array $refused): array => [
			'flagged_source' => $accepted,
			'sprayed_password' => $refused,
			'protected_account' => $accepted,
			'breached_password' => $refused,
			'risky_network' => $accepted,
			'risk_high' => $accepted,
			'admin_outside_networks' => $refused,
		];
		// account => [per reason, coverage: has an email address, has a second factor, can confirm by itself]
		yield 'nothing' => [[], $all($none), [false, false, false]];
		yield 'a second factor' => [['secondFactor' => true], $all([['second_factor'], true]), [false, true, true]];
		yield 'a second factor set up from an unconfirmed session' => [['secondFactor' => true, 'untrusted' => true], $all($none), [false, true, false]];
		yield 'backup codes only' => [['backupOnly' => true], $all($none), [false, false, false]];
		yield 'an email address' => [['email' => 'alice@example.com'], $all([['email_code'], true]), [true, false, true]];
		yield 'an email address, but the server sends no mail' => [['email' => 'alice@example.com', 'mailOff' => true], $all($none), [true, false, false]];
		yield 'an invalid email address' => [['email' => 'not an address'], $all($none), [false, false, false]];
		yield 'a known device in this browser' => [['deviceHere' => true], $device([['known_device'], true], $none), [false, false, false]];
		yield 'a known device in another browser' => [['deviceElsewhere' => true], $device([[], true], $none), [false, false, false]];
		yield 'administrators who can approve' => [['approvers' => true], $all([['admin_approval'], true]), [false, false, false]];
		yield 'everything' => [
			['secondFactor' => true, 'email' => 'alice@example.com', 'deviceHere' => true, 'approvers' => true],
			$device([['second_factor', 'known_device', 'email_code', 'admin_approval'], true], [['second_factor', 'email_code', 'admin_approval'], true]),
			[true, true, true],
		];
	}

	/**
	 * @param array<string, bool|string> $account
	 * @param array<string, array{list<string>, bool}> $expected
	 * @param array{bool, bool, bool} $coverage
	 */
	#[DataProvider('accounts')]
	public function testWhatEachReasonCanBeConfirmedWith(array $account, array $expected, array $coverage): void {
		$this->account = $account;
		$user = $this->user();
		$policy = $this->policy();
		$answers = [];
		foreach (StepUpPolicy::cases() as $reason) {
			$answers[$reason->value] = [
				array_map(static fn (IConfirmationMethod $m): string => $m->id(), $policy->methodsForAll($user, [$reason])),
				$policy->canConfirmInBrowser($user, [$reason]),
			];
		}
		$this->assertSame($expected, $answers);
		$admins = $this->coverage()->admins();
		$this->assertSame($coverage, [
			!in_array('alice', $admins['withoutEmail'], true),
			!in_array('alice', $admins['withoutSecondFactor'], true),
			!in_array('alice', $admins['withNeither'], true),
		]);
		$this->assertSame($coverage[2], $this->accountMethods()->any($user), 'the report and a login agree');
	}

	private function user(): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$user->method('getEMailAddress')->willReturn($this->account['email'] ?? null);
		return $user;
	}

	private function policy(): ConfirmationPolicy {
		$settings = $this->createMock(AppSettings::class);
		$settings->method('stepUpKnownDeviceOkFor')->willReturn(['flagged_source', 'protected_account', 'risky_network', 'risk_high']);
		$settings->method('stepUpAdminApproval')->willReturn(true);
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(fn (string $class): object => match ($class) {
			SecondFactorMethod::class => new SecondFactorMethod($this->challenges(), $this->accountMethods()),
			KnownDeviceMethod::class => new KnownDeviceMethod($this->devices(), $settings),
			EmailCodeMethod::class => new EmailCodeMethod($this->codes(), $this->accountMethods()),
			AdminApprovalMethod::class => new AdminApprovalMethod($this->createMock(ApprovalService::class), $this->createMock(ApprovalMapper::class), $this->approvers(), $settings, $this->createMock(ITimeFactory::class)),
			default => throw new \LogicException($class),
		});
		return new ConfirmationPolicy($settings, $container, $this->createMock(LoggerInterface::class));
	}

	private function challenges(): IChallengeRequester {
		$challenges = $this->createMock(IChallengeRequester::class);
		$challenges->method('isAvailable')->willReturn(($this->account['secondFactor'] ?? false) || ($this->account['backupOnly'] ?? false));
		return $challenges;
	}

	private function registry(): IRegistry {
		$states = [];
		if ($this->account['secondFactor'] ?? false) {
			$states = ['totp' => true, 'backup_codes' => true];
		} elseif ($this->account['backupOnly'] ?? false) {
			$states = ['totp' => false, 'backup_codes' => true];
		}
		$registry = $this->createMock(IRegistry::class);
		$registry->method('getProviderStates')->willReturn($states);
		return $registry;
	}

	private function untrusted(): UntrustedSecondFactors {
		$untrusted = $this->createMock(UntrustedSecondFactors::class);
		$marked = $this->account['untrusted'] ?? false;
		$untrusted->method('marks')->willReturn($marked ? ['totp' => 1] : []);
		$untrusted->method('isTrusted')->willReturn(!$marked);
		return $untrusted;
	}

	private function devices(): KnownDevices {
		$devices = $this->createMock(KnownDevices::class);
		$devices->method('recognise')->willReturn(($this->account['deviceHere'] ?? false) ? new KnownDevice(1, 'alice', 'firefox', 'linux', 'Firefox on Linux', null, 1, 1) : null);
		$devices->method('hasDevices')->willReturn(($this->account['deviceHere'] ?? false) || ($this->account['deviceElsewhere'] ?? false));
		return $devices;
	}

	private function accountMethods(): AccountMethods {
		return new AccountMethods($this->mails(), $this->secondFactors());
	}

	private function mails(): MailReach {
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturnCallback(fn (string $key, string $default): string => $key === 'mail_smtpmode' && ($this->account['mailOff'] ?? false) ? 'null' : $default);
		return new MailReach(Server::get(IEmailValidator::class), $config);
	}

	private function secondFactors(): SecondFactors {
		return new SecondFactors($this->registry(), $this->createMock(ProviderLoader::class), $this->untrusted(), $this->createMock(LoggerInterface::class));
	}

	private function codes(): EmailCodes {
		return new EmailCodes(
			$this->createMock(ISecureRandom::class),
			$this->createMock(IHasher::class),
			$this->createMock(Mails::class),
			$this->createMock(UserMessages::class),
			$this->createMock(ITimeFactory::class),
			$this->createMock(LoginConfirmationStore::class),
			$this->createMock(IUserConfig::class),
		);
	}

	private function approvers(): Approvers {
		$approvers = $this->createMock(Approvers::class);
		$approvers->method('except')->willReturn(($this->account['approvers'] ?? false) ? [$this->createMock(IUser::class)] : []);
		$approvers->method('all')->willReturn([$this->user()]);
		return $approvers;
	}

	private function coverage(): ConfirmationCoverage {
		return new ConfirmationCoverage(
			$this->createMock(IDBConnection::class),
			$this->createMock(IUserManager::class),
			$this->createMock(IGroupManager::class),
			$this->approvers(),
			$this->accountMethods(),
			$this->secondFactors(),
			$this->mails(),
			$this->createMock(Caches::class),
			$this->createMock(ITimeFactory::class),
			$this->createMock(AppState::class),
		);
	}
}
