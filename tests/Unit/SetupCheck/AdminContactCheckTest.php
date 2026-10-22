<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\SetupCheck;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Admin\SetupProblems;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\SetupCheck\AdminContactCheck;
use OCA\IntrusionDetection\SetupCheck\Finding;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\IDBConnection;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Server;
use OCP\SetupCheck\SetupResult;
use Test\TestCase;

class AdminContactCheckTest extends TestCase {
	public function testEveryAdminWithEmailAndSecondFactorIsFine(): void {
		$result = $this->check([['alice', 'alice@example.com', ['totp' => true]], ['bob', 'bob@example.com', ['webauthn' => true]]]);
		$this->assertSame(SetupResult::SUCCESS, $result->getSeverity());
	}

	public function testAnAdminWithoutEmailIsAWarning(): void {
		$result = $this->check([['alice', 'alice@example.com', ['totp' => true]], ['bob', null, ['totp' => true]]]);
		$this->assertSame(SetupResult::WARNING, $result->getSeverity());
		$this->assertStringContainsString('1 administrator has no email address', (string)$result->getDescription());
		$this->assertStringContainsString('bob', (string)$result->getDescription());
		$this->assertStringNotContainsString('alice', (string)$result->getDescription());
		$this->assertStringEndsWith('#settings-confirmation', (string)$result->getLinkToDoc(), 'It links to the login confirmation settings');
	}

	public function testAnAdminWithOnlyBackupCodesHasNoSecondFactor(): void {
		$result = $this->check([['alice', 'alice@example.com', ['backup_codes' => true, 'totp' => false]]]);
		$this->assertSame(SetupResult::WARNING, $result->getSeverity());
		$this->assertStringContainsString('has no second factor', (string)$result->getDescription());
	}

	public function testNoAdminWithEmailIsAWarning(): void {
		$result = $this->check([['alice', null, ['totp' => true]], ['bob', '', ['totp' => true]]]);
		$this->assertSame(SetupResult::WARNING, $result->getSeverity());
		$this->assertStringContainsString('No administrator has an email address', (string)$result->getDescription());
	}

	public function testNoAdminWithEitherIsAnError(): void {
		$result = $this->check([['alice', null, []], ['bob', '', ['backup_codes' => true]]]);
		$this->assertSame(SetupResult::ERROR, $result->getSeverity());
	}

	public function testOneAdminWithEmailAndAnotherWithASecondFactorIsOnlyAWarning(): void {
		$result = $this->check([['alice', 'alice@example.com', []], ['bob', null, ['totp' => true]]]);
		$this->assertSame(SetupResult::WARNING, $result->getSeverity());
	}

	public function testLongListsAreShortened(): void {
		$admins = [];
		for ($i = 1; $i <= 12; $i++) {
			$admins[] = ['admin' . $i, null, ['totp' => true]];
		}
		$admins[] = ['carol', 'carol@example.com', ['totp' => true]];
		$this->assertStringContainsString('and 2 more', (string)$this->check($admins)->getDescription());
	}

	public function testTheAdministratorsAreCheckedOnceAnHour(): void {
		$approvers = $this->createMock(Approvers::class);
		$approvers->expects($this->once())->method('all')->willReturn([$this->admin('alice', null)]);
		$registry = $this->createMock(IRegistry::class);
		$registry->method('getProviderStates')->willReturn([]);
		$check = $this->instance($approvers, $registry);
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$this->assertSame(Finding::LEVEL_ERROR, $check->finding($l)?->level);
		$this->assertSame(Finding::LEVEL_ERROR, $check->finding($l)?->level, 'The second run uses the cached result');
	}

	public function testAdministratorsWhoCannotConfirmFromOutsideTheTrustedNetworksAreNamed(): void {
		$admins = [['alice', 'alice@example.com', ['totp' => true]], ['bob', null, []]];
		$this->assertStringNotContainsString('trusted networks', (string)$this->check($admins)->getDescription(), 'Not while the switch is off');

		$result = $this->check($admins, true);
		$this->assertSame(SetupResult::WARNING, $result->getSeverity());
		$this->assertStringContainsString('Administrators log in from trusted networks only, but 1 administrator has neither an email address nor a second factor to confirm a login from anywhere else: bob.', (string)$result->getDescription());

		$this->assertStringContainsString('2 administrators have neither', (string)$this->check([['alice', null, []], ['bob', null, []]], true)->getDescription());
		$this->assertSame(SetupResult::SUCCESS, $this->check([['alice', 'alice@example.com', ['totp' => true]]], true)->getSeverity());
	}

	public function testItIsShownUnderTheStatusBanner(): void {
		$this->assertContains(AdminContactCheck::class, SetupProblems::CHECKS);
	}

	/**
	 * @param list<array{string, ?string, array<string, bool>}> $admins
	 */
	private function check(array $admins, bool $trustedNetworksOnly = false): SetupResult {
		$users = [];
		$states = [];
		foreach ($admins as [$uid, $email, $providers]) {
			$users[] = $this->admin($uid, $email);
			$states[$uid] = $providers;
		}
		$approvers = $this->createMock(Approvers::class);
		$approvers->method('all')->willReturn($users);
		$registry = $this->createMock(IRegistry::class);
		$registry->method('getProviderStates')->willReturnCallback(static fn (IUser $u): array => $states[$u->getUID()]);
		return $this->instance($approvers, $registry, $trustedNetworksOnly)->run();
	}

	private function admin(string $uid, ?string $email): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($uid);
		$user->method('getEMailAddress')->willReturn($email);
		return $user;
	}

	private function instance(Approvers $approvers, IRegistry $registry, bool $trustedNetworksOnly = false): AdminContactCheck {
		$cache = new ArrayCache();
		$cacheFactory = new FixedCaches($cache);
		$coverage = new ConfirmationCoverage(
			$this->createMock(IDBConnection::class),
			$this->createMock(IUserManager::class),
			$this->createMock(IGroupManager::class),
			$approvers,
			$registry,
			$cacheFactory,
			$this->createMock(\OCP\AppFramework\Utility\ITimeFactory::class),
			$this->createMock(\OCA\IntrusionDetection\State\AppState::class),
		);
		$links = $this->createMock(AdminLinks::class);
		$links->method('adminPage')->willReturn('https://cloud.example.com/settings/admin/intrusion_detection');
		$settings = $this->createMock(Settings::class);
		$settings->method('getBool')->willReturnCallback(static fn (string $name): bool => $name === GlobalSettings::ADMIN_TRUSTED_NETWORKS_ONLY && $trustedNetworksOnly);
		return new AdminContactCheck(Server::get(IFactory::class)->get('intrusion_detection', 'en'), $links, $coverage, $settings);
	}
}
