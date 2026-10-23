<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\AdminChange;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\AdminGrantGate;
use OCA\IntrusionDetection\AdminChange\DelegatedGroups;
use OCA\IntrusionDetection\AdminChange\GrantPermit;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Definition\Mode;
use OCP\Group\Backend\INamedBackend;
use OCP\GroupInterface;
use OCP\IGroup;
use OCP\IGroupManager;
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

	public function testAGroupWithDelegatedAdminSettingsNeedsApprovalToo(): void {
		$this->assertSame(AdminGrantGate::NEEDS_APPROVAL, $this->gate()->decide($this->group('helpdesk'), $this->user('bob')));
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

	public function testMembershipsADirectoryHoldsAreExempt(): void {
		$this->assertSame(AdminChange::EXEMPT_DIRECTORY, $this->gate(directory: ['bob'])->decide($this->group('admin'), $this->user('bob')));
		$this->assertTrue($this->gate(directory: ['bob'])->isDirectoryBacked($this->group('admin'), $this->user('bob')));
	}

	public function testAGroupNameADirectoryAlsoHasIsNotEnough(): void {
		$this->assertSame(AdminGrantGate::NEEDS_APPROVAL, $this->gate(directory: ['dave'])->decide($this->group('admin'), $this->user('bob')));
		$this->assertFalse($this->gate()->isDirectoryBacked($this->group('admin'), $this->user('bob')), 'Nextcloud\'s own database is no directory');
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

	/**
	 * @param ?list<string> $directory the members of "admin" in a user directory; null without one
	 */
	private function gate(bool $required = true, Mode $mode = Mode::Protect, bool $enabled = true, bool $commandLine = false, bool $console = false, ?array $directory = null): AdminGrantGate {
		$appSettings = $this->createMock(AppSettings::class);
		$appSettings->method('adminChangeRequireApproval')->willReturn($required);
		$appSettings->method('isEnabled')->willReturn($enabled);
		$settings = $this->createMock(CheckSettings::class);
		$settings->method('configuredMode')->willReturn($mode);
		$actors = $this->createMock(ActorResolver::class);
		$actors->method('isCommandLine')->willReturn($commandLine);
		$actors->method('isConsole')->willReturn($console);
		$backends = [$this->backend('Database', ['bob', 'dave'])];
		if ($directory !== null) {
			$backends[] = $this->backend('LDAP', $directory);
		}
		$groupManager = $this->createMock(IGroupManager::class);
		$groupManager->method('getBackends')->willReturn($backends);
		$delegated = $this->createMock(DelegatedGroups::class);
		$delegated->method('of')->willReturnCallback(static fn (string $gid): ?array => $gid === 'helpdesk' ? ['Users'] : null);
		return new AdminGrantGate($appSettings, $settings, $actors, $this->permit, $groupManager, $delegated);
	}

	/**
	 * A group backend that has the group "admin" with these members.
	 *
	 * @param list<string> $members
	 */
	private function backend(string $name, array $members): GroupInterface&INamedBackend {
		$backend = $this->createMockForIntersectionOfInterfaces([GroupInterface::class, INamedBackend::class]);
		$backend->method('getBackendName')->willReturn($name);
		$backend->method('groupExists')->willReturnCallback(static fn (string $gid): bool => $gid === 'admin');
		$backend->method('inGroup')->willReturnCallback(static fn (string $uid, string $gid): bool => $gid === 'admin' && in_array($uid, $members, true));
		return $backend;
	}

	private function group(string $gid): IGroup {
		$group = $this->createMock(IGroup::class);
		$group->method('getGID')->willReturn($gid);
		return $group;
	}

	private function user(string $uid): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($uid);
		return $user;
	}
}
