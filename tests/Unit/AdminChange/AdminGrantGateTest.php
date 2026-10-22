<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\AdminChange;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\AdminGrantGate;
use OCA\IntrusionDetection\AdminChange\GrantPermit;
use OCA\IntrusionDetection\Check\Checks\AdminChange;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Definition\Mode;
use OCP\IGroup;
use OCP\IUser;
use Test\TestCase;

class AdminGrantGateTest extends TestCase {
	private GrantPermit $permit;

	protected function setUp(): void {
		parent::setUp();
		$this->permit = new GrantPermit();
	}

	public function testAWebAdditionToTheAdminGroupNeedsApproval(): void {
		$this->assertSame(AdminGrantGate::NEEDS_APPROVAL, $this->gate()->decide($this->group('admin'), $this->user('bob')));
	}

	public function testOtherGroupsNeverNeedApproval(): void {
		$this->assertSame(AdminGrantGate::NOT_NEEDED, $this->gate()->decide($this->group('delegated-admins'), $this->user('bob')));
	}

	public function testNothingIsNeededWhileTheSettingIsOff(): void {
		$this->assertSame(AdminGrantGate::NOT_NEEDED, $this->gate(required: false)->decide($this->group('admin'), $this->user('bob')));
	}

	public function testNothingIsNeededUnlessTheCheckProtects(): void {
		$this->assertSame(AdminGrantGate::NOT_NEEDED, $this->gate(mode: Mode::Observe)->decide($this->group('admin'), $this->user('bob')));
		$this->assertSame(AdminGrantGate::NOT_NEEDED, $this->gate(enabled: false)->decide($this->group('admin'), $this->user('bob')));
	}

	public function testOccIsExempt(): void {
		$this->assertSame(AdminChange::EXEMPT_OCC, $this->gate(commandLine: true, console: true)->decide($this->group('admin'), $this->user('bob')));
	}

	public function testBackgroundJobsOnTheCommandLineAreExempt(): void {
		$this->assertSame(AdminChange::EXEMPT_CRON, $this->gate(commandLine: true)->decide($this->group('admin'), $this->user('bob')));
	}

	public function testDirectoryBackedGroupsAreExempt(): void {
		$this->assertSame(AdminChange::EXEMPT_DIRECTORY, $this->gate()->decide($this->group('admin', ['Database', 'LDAP']), $this->user('bob')));
		$this->assertTrue($this->gate()->isDirectoryBacked($this->group('admin', ['LDAP'])));
		$this->assertFalse($this->gate()->isDirectoryBacked($this->group('admin', ['Database'])));
	}

	public function testAnApprovedAdditionPassesOnceWithItsFacts(): void {
		$gate = $this->gate();
		$this->permit->allow('bob', 'admin', ['approval' => 3, 'approved_by' => 'carol']);
		$this->assertSame(AdminGrantGate::APPROVED, $gate->decide($this->group('admin'), $this->user('bob')));
		$this->assertSame(['approval' => 3, 'approved_by' => 'carol'], $gate->permitFacts());
		$this->assertSame(AdminGrantGate::NEEDS_APPROVAL, $gate->decide($this->group('admin'), $this->user('bob')), 'The permit cannot be replayed');
		$this->assertSame([], $gate->permitFacts());
	}

	public function testAPermitForAnotherAccountDoesNotHelp(): void {
		$this->permit->allow('bob', 'admin');
		$this->assertSame(AdminGrantGate::NEEDS_APPROVAL, $this->gate()->decide($this->group('admin'), $this->user('mallory')));
	}

	private function gate(bool $required = true, Mode $mode = Mode::Protect, bool $enabled = true, bool $commandLine = false, bool $console = false): AdminGrantGate {
		$settings = $this->createMock(Settings::class);
		$settings->method('getBool')->willReturnCallback(static fn (string $name): bool => $name === GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL && $required);
		$settings->method('isEnabled')->willReturn($enabled);
		$settings->method('configuredMode')->willReturn($mode);
		$actors = $this->createMock(ActorResolver::class);
		$actors->method('isCommandLine')->willReturn($commandLine);
		$actors->method('isConsole')->willReturn($console);
		return new AdminGrantGate($settings, $actors, $this->permit);
	}

	/**
	 * @param list<string> $backends
	 */
	private function group(string $gid, array $backends = ['Database']): IGroup {
		$group = $this->createMock(IGroup::class);
		$group->method('getGID')->willReturn($gid);
		$group->method('getBackendNames')->willReturn($backends);
		return $group;
	}

	private function user(string $uid): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($uid);
		return $user;
	}
}
