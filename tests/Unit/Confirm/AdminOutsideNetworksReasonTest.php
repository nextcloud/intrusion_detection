<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Confirm;

use OCA\IntrusionDetection\AdminChange\DelegatedGroups;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\Methods\KnownDeviceMethod;
use OCA\IntrusionDetection\Confirm\Reasons\AdminOutsideNetworksReason;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpReasons;
use OCA\IntrusionDetection\Login\LoginContext;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IGroupManager;
use OCP\IUser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class AdminOutsideNetworksReasonTest extends TestCase {
	private AppSettings&MockObject $settings;
	private IGroupManager&MockObject $groups;
	private DelegatedGroups&MockObject $delegated;
	private bool $on = true;
	/** @var list<string> */
	private array $networks = ['192.0.2.0/24', '2001:db8:1::/48'];

	protected function setUp(): void {
		parent::setUp();
		$this->settings = $this->createMock(AppSettings::class);
		$this->settings->method('adminTrustedNetworksOnly')->willReturnCallback(fn (): bool => $this->on);
		$this->settings->method('riskyNetworkOfficeNetworks')->willReturnCallback(fn (): array => $this->networks);
		$this->groups = $this->createMock(IGroupManager::class);
		$this->delegated = $this->createMock(DelegatedGroups::class);
	}

	public function testItIsAStepUpReason(): void {
		$this->assertContains(AdminOutsideNetworksReason::class, StepUpReasons::PROVIDERS);
		$this->assertSame(StepUpPolicy::AdminOutsideNetworks, AdminOutsideNetworksReason::policy());
		$this->assertFalse(StepUpPolicy::AdminOutsideNetworks->allowsFamiliarApps(), 'Strict for apps sending the password');
		$this->assertContains(StepUpPolicy::AdminOutsideNetworks, KnownDeviceMethod::NEVER, 'A remembered device does not change the network');
	}

	public function testNothingIsReadWhileTheSwitchIsOff(): void {
		$this->on = false;
		$this->settings->expects($this->never())->method('riskyNetworkOfficeNetworks');
		$this->groups->expects($this->never())->method('isInGroup');
		$this->delegated->expects($this->never())->method('all');
		$this->assertFalse($this->reason()->applies($this->login('203.0.113.9')));
	}

	/**
	 * @return array<string, array{?string, bool}>
	 */
	public static function addresses(): array {
		return [
			'IPv4 inside' => ['192.0.2.40', false],
			'IPv4 outside' => ['203.0.113.9', true],
			'IPv6 inside' => ['2001:db8:1:5::1', false],
			'IPv6 outside' => ['2001:db8:2::1', true],
			'no address' => [null, true],
		];
	}

	#[DataProvider('addresses')]
	public function testAnAdministratorIsAskedOutsideTheTrustedNetworksOnly(?string $ip, bool $applies): void {
		$this->groups->method('isInGroup')->with('alice', 'admin')->willReturn(true);
		$this->assertSame($applies, $this->reason()->applies($this->login($ip)));
	}

	public function testInsideTheNetworksNoGroupIsLookedUp(): void {
		$this->groups->expects($this->never())->method('isInGroup');
		$this->assertFalse($this->reason()->applies($this->login('192.0.2.40')));
	}

	public function testWithoutTrustedNetworksEveryAddressIsOutside(): void {
		$this->networks = [];
		$this->groups->method('isInGroup')->willReturn(true);
		$this->assertTrue($this->reason()->applies($this->login('192.0.2.40')));
	}

	public function testDelegatedAdministratorsCountAndOtherAccountsDoNot(): void {
		$this->groups->method('isInGroup')->willReturn(false);
		$this->groups->method('getUserGroupIds')->willReturn(['staff', 'helpdesk']);
		$this->delegated->method('all')->willReturn(['helpdesk' => ['Users']]);
		$this->assertTrue($this->reason()->applies($this->login('203.0.113.9')));

		$other = $this->createMock(DelegatedGroups::class);
		$other->method('all')->willReturn(['finance' => ['Server']]);
		$this->delegated = $other;
		$this->assertFalse($this->reason()->applies($this->login('203.0.113.9')));
	}

	public function testWithoutDelegationsTheGroupsOfAnOrdinaryAccountAreNotRead(): void {
		$this->groups->method('isInGroup')->willReturn(false);
		$this->groups->expects($this->never())->method('getUserGroupIds');
		$this->delegated->method('all')->willReturn([]);
		$this->assertFalse($this->reason()->applies($this->login('203.0.113.9')));
	}

	private function reason(): AdminOutsideNetworksReason {
		return new AdminOutsideNetworksReason($this->settings, $this->groups, $this->delegated);
	}

	private function login(?string $ip): LoginContext {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		return new LoginContext($user, $ip === null ? null : SourceKey::fromIp($ip), true, null, [], false);
	}
}
