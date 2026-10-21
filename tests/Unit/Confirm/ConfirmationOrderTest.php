<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Confirm;

use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\ConfirmationPolicy;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\Methods\AdminApprovalMethod;
use OCA\IntrusionDetection\Confirm\Methods\EmailCodeMethod;
use OCA\IntrusionDetection\Confirm\Methods\KnownDeviceMethod;
use OCA\IntrusionDetection\Confirm\Methods\SecondFactorMethod;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\KnownDevice\KnownDevice;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\TwoFactorAuth\IChallengeRequester;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\IUser;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * The four confirmation methods in their real order (concept section
 * 11.5): second factor, known device, email code, administrator approval,
 * for every combination of what the account has and every policy.
 */
class ConfirmationOrderTest extends TestCase {
	private const NOW = 1_800_000_000;

	private bool $secondFactor = false;
	private bool $knownDevice = false;
	private bool $email = false;
	private bool $approval = false;
	private bool $otherApprovers = true;
	/** @var list<string> */
	private array $knownDeviceOk = KnownDeviceMethod::DEFAULT_POLICIES;
	private ?Approval $requested = null;

	/**
	 * @return \Generator<string, array{bool, bool, bool, bool}>
	 */
	public static function accounts(): \Generator {
		foreach ([false, true] as $secondFactor) {
			foreach ([false, true] as $device) {
				foreach ([false, true] as $email) {
					foreach ([false, true] as $approval) {
						$name = implode(', ', array_keys(array_filter(['second factor' => $secondFactor, 'known device' => $device, 'email' => $email, 'admin approval' => $approval]))) ?: 'nothing';
						yield $name => [$secondFactor, $device, $email, $approval];
					}
				}
			}
		}
	}

	#[DataProvider('accounts')]
	public function testTheMethodsComeInOrderForEveryPolicy(bool $secondFactor, bool $device, bool $email, bool $approval): void {
		[$this->secondFactor, $this->knownDevice, $this->email, $this->approval] = [$secondFactor, $device, $email, $approval];
		$policy = $this->policy();
		$user = $this->user();
		foreach (StepUpPolicy::cases() as $reason) {
			$deviceCounts = $device && in_array($reason->value, KnownDeviceMethod::DEFAULT_POLICIES, true);
			$expected = array_keys(array_filter([
				IConfirmationMethod::SECOND_FACTOR => $secondFactor,
				IConfirmationMethod::KNOWN_DEVICE => $deviceCounts,
				IConfirmationMethod::EMAIL_CODE => $email,
				IConfirmationMethod::ADMIN_APPROVAL => $approval,
			]));
			$this->assertSame($expected, $this->ids($policy->methodsFor($user, $reason)), $reason->value);
		}
	}

	/**
	 * @return array<string, array{StepUpPolicy}>
	 */
	public static function passwordAtRisk(): array {
		return [
			'sprayed password' => [StepUpPolicy::SprayedPassword],
			'breached password' => [StepUpPolicy::BreachedPassword],
		];
	}

	#[DataProvider('passwordAtRisk')]
	public function testAKnownDeviceNeverConfirmsWhenThePasswordIsAtRisk(StepUpPolicy $reason): void {
		$this->knownDevice = true;
		$this->knownDeviceOk = array_map(static fn (StepUpPolicy $p): string => $p->value, StepUpPolicy::cases());
		$method = $this->knownDeviceMethod();
		$this->assertFalse($method->isAvailable($this->user(), $reason), 'Not even when the setting names it');
		$this->assertFalse($method->accepts($reason));
		$this->assertTrue($method->isAvailable($this->user(), StepUpPolicy::FlaggedSource));
		$this->assertSame([], $this->ids($this->policy()->methodsForAll($this->user(), [StepUpPolicy::FlaggedSource, $reason])), 'A login with both reasons cannot be confirmed by the device');
	}

	public function testTheSettingDecidesForTheOtherPolicies(): void {
		$this->knownDevice = true;
		$this->knownDeviceOk = ['protected_account'];
		$method = $this->knownDeviceMethod();
		$this->assertFalse($method->isAvailable($this->user(), StepUpPolicy::FlaggedSource));
		$this->assertTrue($method->isAvailable($this->user(), StepUpPolicy::ProtectedAccount));
	}

	public function testAKnownDeviceConfirmsSilently(): void {
		$this->knownDevice = true;
		$state = new StepUpState('alice', StepUpState::PENDING, ['flagged_source'], self::NOW, self::NOW + 900);
		$this->assertSame(IConfirmationMethod::CONFIRMED, $this->knownDeviceMethod()->begin($this->user(), $state));
		$this->knownDevice = false;
		$this->assertSame(IConfirmationMethod::UNAVAILABLE, $this->knownDeviceMethod()->begin($this->user(), $state));
	}

	public function testAdminApprovalNeedsTheSettingAndAnotherAdministrator(): void {
		$this->approval = true;
		$this->assertTrue($this->approvalMethod()->isAvailable($this->user(), StepUpPolicy::ProtectedAccount));
		$this->otherApprovers = false;
		$this->assertFalse($this->approvalMethod()->isAvailable($this->user(), StepUpPolicy::FlaggedSource), 'Nobody else could approve');
		$this->otherApprovers = true;
		$this->approval = false;
		$this->assertFalse($this->approvalMethod()->isAvailable($this->user(), StepUpPolicy::FlaggedSource), 'Switched off');
	}

	public function testAdminApprovalWaitsAsLongAsTheRequest(): void {
		$this->approval = true;
		$this->requested = $this->approvalRow(Approval::STATUS_PENDING, self::NOW + 1800);
		$state = new StepUpState('alice', StepUpState::PENDING, ['flagged_source'], self::NOW, self::NOW + 900, '203.0.113.7');
		$this->assertSame(IConfirmationMethod::PENDING, $this->approvalMethod()->begin($this->user(), $state));
		$this->assertSame(41, $state->approvalId);
		$this->assertSame(self::NOW + 1800, $state->deadline, 'The login may wait until the request expires');

		$this->requested = null;
		$other = new StepUpState('alice', StepUpState::PENDING, ['flagged_source'], self::NOW, self::NOW + 900);
		$this->assertSame(IConfirmationMethod::UNAVAILABLE, $this->approvalMethod()->begin($this->user(), $other), 'No request could be stored');
		$this->assertNull($other->approvalId);
	}

	/**
	 * @return array<string, array{string, ?string, int, string}>
	 */
	public static function statuses(): array {
		return [
			'waiting' => [Approval::STATUS_PENDING, null, self::NOW + 60, AdminApprovalMethod::STATUS_PENDING],
			'waited too long' => [Approval::STATUS_PENDING, null, self::NOW, AdminApprovalMethod::STATUS_EXPIRED],
			'approved by another administrator' => [Approval::STATUS_APPROVED, 'carol', self::NOW + 60, AdminApprovalMethod::STATUS_APPROVED],
			'approved by the account itself' => [Approval::STATUS_APPROVED, 'alice', self::NOW + 60, AdminApprovalMethod::STATUS_REJECTED],
			'rejected' => [Approval::STATUS_REJECTED, 'carol', self::NOW + 60, AdminApprovalMethod::STATUS_REJECTED],
			'expired' => [Approval::STATUS_EXPIRED, null, self::NOW - 60, AdminApprovalMethod::STATUS_EXPIRED],
		];
	}

	#[DataProvider('statuses')]
	public function testTheStatusOfTheRequest(string $status, ?string $decidedBy, int $expiresAt, string $expected): void {
		$row = $this->approvalRow($status, $expiresAt);
		$row->setDecidedBy($decidedBy);
		$state = new StepUpState('alice', StepUpState::PENDING, ['flagged_source'], self::NOW, self::NOW + 900, approvalId: 41);
		$this->assertSame($expected, $this->approvalMethod($row)->status($this->user(), $state));
	}

	public function testAnotherAccountsRequestIsNotThisLoginsRequest(): void {
		$row = $this->approvalRow(Approval::STATUS_APPROVED, self::NOW + 60);
		$row->setSubjectUid('mallory');
		$row->setDecidedBy('carol');
		$state = new StepUpState('alice', StepUpState::PENDING, ['flagged_source'], self::NOW, self::NOW + 900, approvalId: 41);
		$this->assertSame(AdminApprovalMethod::STATUS_NONE, $this->approvalMethod($row)->status($this->user(), $state));
	}

	private function policy(): ConfirmationPolicy {
		$methods = [
			SecondFactorMethod::class => $this->secondFactorMethod(),
			KnownDeviceMethod::class => $this->knownDeviceMethod(),
			EmailCodeMethod::class => $this->emailMethod(),
			AdminApprovalMethod::class => $this->approvalMethod(),
		];
		$this->assertSame(array_keys($methods), ConfirmationPolicy::METHODS, 'The order of concept section 11.5');
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $id): object => $methods[$id]);
		return new ConfirmationPolicy($this->settings(), $container, $this->createMock(LoggerInterface::class));
	}

	private function secondFactorMethod(): SecondFactorMethod {
		$challenges = $this->createMock(IChallengeRequester::class);
		$challenges->method('isAvailable')->willReturnCallback(fn (): bool => $this->secondFactor);
		$registry = $this->createMock(IRegistry::class);
		$registry->method('getProviderStates')->willReturnCallback(fn (): array => $this->secondFactor ? ['totp' => true] : []);
		return new SecondFactorMethod($challenges, $registry);
	}

	private function knownDeviceMethod(): KnownDeviceMethod {
		$devices = $this->createMock(KnownDevices::class);
		$devices->method('recognise')->willReturnCallback(fn (): ?KnownDevice => $this->knownDevice ? new KnownDevice(3, 'alice', 'firefox', 'linux', 'Firefox on Linux', '203.0.113.0/24', self::NOW - 86400, self::NOW - 86400) : null);
		return new KnownDeviceMethod($devices, $this->settings());
	}

	private function emailMethod(): EmailCodeMethod {
		$codes = $this->createMock(EmailCodes::class);
		$codes->method('isAvailable')->willReturnCallback(fn (): bool => $this->email);
		return new EmailCodeMethod($codes);
	}

	private function approvalMethod(?Approval $row = null): AdminApprovalMethod {
		$service = $this->createMock(ApprovalService::class);
		$service->method('requestLogin')->willReturnCallback(fn (): ?Approval => $this->requested);
		$mapper = $this->createMock(ApprovalMapper::class);
		if ($row !== null) {
			$mapper->method('findById')->willReturn($row);
		}
		$approvers = $this->createMock(Approvers::class);
		$approvers->method('except')->willReturnCallback(fn (): array => $this->otherApprovers ? [$this->createMock(IUser::class)] : []);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(self::NOW);
		return new AdminApprovalMethod($service, $mapper, $approvers, $this->settings(), $time);
	}

	private function approvalRow(string $status, int $expiresAt): Approval {
		$row = new Approval();
		$row->setId(41);
		$row->setKind(Approval::KIND_LOGIN);
		$row->setSubjectUid('alice');
		$row->setRequestedBy('alice');
		$row->setStatus($status);
		$row->setCreatedAt(self::NOW - 60);
		$row->setExpiresAt($expiresAt);
		return $row;
	}

	private function settings(): Settings {
		$settings = $this->createMock(Settings::class);
		$settings->method('global')->willReturnCallback(fn (string $name): array|string => $name === GlobalSettings::STEP_UP_KNOWN_DEVICE_OK_FOR ? $this->knownDeviceOk : '');
		$settings->method('getBool')->willReturnCallback(fn (string $name): bool => $name === GlobalSettings::STEP_UP_ADMIN_APPROVAL && $this->approval);
		$settings->method('getInt')->willReturn(1800);
		return $settings;
	}

	private function user(): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		return $user;
	}

	/**
	 * @param list<IConfirmationMethod> $methods
	 * @return list<string>
	 */
	private function ids(array $methods): array {
		return array_map(static fn (IConfirmationMethod $m): string => $m->id(), $methods);
	}
}
