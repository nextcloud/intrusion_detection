<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\SetupCheck;

use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\SetupCheck\AdminContactCheck;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\IUser;
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

	/**
	 * @param list<array{string, ?string, array<string, bool>}> $admins
	 */
	private function check(array $admins): SetupResult {
		$users = [];
		$states = [];
		foreach ($admins as [$uid, $email, $providers]) {
			$user = $this->createMock(IUser::class);
			$user->method('getUID')->willReturn($uid);
			$user->method('getEMailAddress')->willReturn($email);
			$users[] = $user;
			$states[$uid] = $providers;
		}
		$approvers = $this->createMock(Approvers::class);
		$approvers->method('all')->willReturn($users);
		$registry = $this->createMock(IRegistry::class);
		$registry->method('getProviderStates')->willReturnCallback(static fn (IUser $u): array => $states[$u->getUID()]);
		return (new AdminContactCheck($approvers, $registry, Server::get(IFactory::class)->get('intrusion_detection', 'en')))->run();
	}
}
