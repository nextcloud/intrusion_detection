<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Login;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Login\EmailAccounts;
use OCP\ICacheFactory;
use OCP\IUser;
use OCP\IUserManager;
use Test\TestCase;

class EmailAccountsTest extends TestCase {
	private function user(string $uid, bool $enabled): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($uid);
		$user->method('isEnabled')->willReturn($enabled);
		return $user;
	}

	public function testRepeatedLookupsOfOneAddressAskCoreOnce(): void {
		$users = $this->createMock(IUserManager::class);
		$users->expects($this->once())->method('getByEmail')->with('Alice@Example.com')->willReturn([$this->user('alice', true)]);
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn(true);
		$factory->method('createDistributed')->willReturn(new ArrayCache());
		$accounts = new EmailAccounts($users, $factory);

		$this->assertSame('alice', $accounts->only('Alice@Example.com'));
		$this->assertSame('alice', $accounts->only('alice@example.com '), 'the same address, from the cache');
	}

	public function testAnAddressWithoutAccountsIsNotKept(): void {
		$users = $this->createMock(IUserManager::class);
		$users->expects($this->exactly(2))->method('getByEmail')->willReturn([]);
		$cache = new ArrayCache();
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn(true);
		$factory->method('createDistributed')->willReturn($cache);
		$accounts = new EmailAccounts($users, $factory);

		$this->assertNull($accounts->only('made-up@example.com'));
		$this->assertNull($accounts->only('made-up@example.com'), 'asked again');
		$this->assertNull($cache->get('email:' . hash('sha256', 'made-up@example.com')));
	}

	public function testOnlyOneAccountCountsAndDisabledOnesOptionally(): void {
		$users = $this->createMock(IUserManager::class);
		$users->method('getByEmail')->willReturnMap([
			['shared@example.com', [$this->user('a', true), $this->user('b', true)]],
			['old@example.com', [$this->user('c', false), $this->user('d', true)]],
			['none@example.com', []],
		]);
		$accounts = new EmailAccounts($users, $this->createMock(ICacheFactory::class));

		$this->assertNull($accounts->only('shared@example.com'));
		$this->assertNull($accounts->only('old@example.com'));
		$this->assertSame('d', $accounts->only('old@example.com', true));
		$this->assertNull($accounts->only('none@example.com'));
	}
}
