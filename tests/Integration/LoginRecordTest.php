<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Listener\LoginRecordListener;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ICacheFactory;
use OCP\IUser;
use OCP\Server;
use OCP\User\Events\UserLoggedInEvent;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Apps and WebDAV clients log in with every request: only the first login
 * per address, account and hour is written.
 */
#[Group('DB')]
class LoginRecordTest extends IntegrationTestCase {
	public function testWithAMemoryCacheOnlyTheFirstLoginOfTheHourReachesTheDatabase(): void {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn(true);
		$factory->method('createDistributed')->willReturn(new ArrayCache());
		$listener = $this->listener($factory, '203.0.113.40');

		$queries = $this->queries();
		$listener->handle($this->event('alice'));
		$first = $this->queries() - $queries;
		$this->assertSame(1, $first, 'one insert');
		for ($i = 0; $i < 5; $i++) {
			$listener->handle($this->event('alice'));
		}
		$this->assertSame($first, $this->queries() - $queries, 'repeated logins write nothing');
		$listener->handle($this->event('bob'));
		$this->assertSame(2, Server::get(LoginMapper::class)->distinctUsersForIp('203.0.113.40', 0));
	}

	public function testWithoutAMemoryCacheEveryLoginIsOneInsertThatSkipsExistingRows(): void {
		$listener = $this->listener($this->createMock(ICacheFactory::class), '203.0.113.41');
		$queries = $this->queries();
		for ($i = 0; $i < 3; $i++) {
			$listener->handle($this->event('alice'));
		}
		$this->assertSame(3, $this->queries() - $queries);
		$this->assertSame(1, Server::get(LoginMapper::class)->distinctUsersForIp('203.0.113.41', 0));
	}

	private function listener(ICacheFactory $factory, string $ip): LoginRecordListener {
		$addresses = $this->createMock(RemoteAddressResolver::class);
		$addresses->method('current')->willReturn(SourceKey::fromIp($ip));
		$addresses->method('isBypassListed')->willReturn(false);
		return new LoginRecordListener(Server::get(Settings::class), Server::get(LoginMapper::class), $addresses, Server::get(ITimeFactory::class), Server::get(LoggerInterface::class), $factory);
	}

	private function event(string $uid): UserLoggedInEvent {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($uid);
		return new UserLoggedInEvent($user, $uid, null, true);
	}

	private function queries(): int {
		return $this->db->getInner()->getStats()['executed'];
	}
}
