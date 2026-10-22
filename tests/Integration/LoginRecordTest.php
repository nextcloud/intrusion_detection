<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Listener\LoginRecordListener;
use OCA\IntrusionDetection\Login\LoginGate;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ISession;
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
		$factory = new FixedCaches(new ArrayCache());
		// One listener per request.
		$request = fn (): LoginRecordListener => $this->listener($factory, '203.0.113.40');

		$queries = $this->queries();
		$request()->handle($this->event('alice'));
		$first = $this->queries() - $queries;
		$this->assertSame(1, $first, 'one insert');
		for ($i = 0; $i < 5; $i++) {
			$request()->handle($this->event('alice'));
		}
		$this->assertSame($first, $this->queries() - $queries, 'repeated logins write nothing');
		$request()->handle($this->event('bob'));
		$this->assertSame(2, count(Server::get(LoginMapper::class)->distinctUidsForIp('203.0.113.40', 0, 100)));
	}

	public function testWithoutAMemoryCacheEveryLoginIsOneReadAndOnlyTheFirstInserts(): void {
		$listener = $this->listener(FixedCaches::none(), '203.0.113.41');
		$queries = $this->queries();
		$listener->handle($this->event('alice'));
		$this->assertSame(2, $this->queries() - $queries, 'a read and the insert');
		$id = $this->lastId();
		$queries = $this->queries();
		for ($i = 0; $i < 3; $i++) {
			$listener->handle($this->event('alice'));
		}
		$this->assertSame(3, $this->queries() - $queries, 'a read each, no insert');
		$listener->handle($this->event('bob'));
		$this->assertSame($id + 1, $this->lastId(), 'no insert that skipped the row used up an id');
		$this->assertSame(2, count(Server::get(LoginMapper::class)->distinctUidsForIp('203.0.113.41', 0, 100)));
	}

	public function testTheLoginHistoryOfTheSameLoginAsksTheGateNoMore(): void {
		$cache = new class extends ArrayCache {
			public int $adds = 0;

			public function add($key, $value, $ttl = 0) {
				$this->adds++;
				return parent::add($key, $value, $ttl);
			}
		};
		$factory = new FixedCaches($cache);
		$gate = new LoginGate($factory, $this->createMock(ISession::class));
		$this->assertTrue($gate->isFirst('alice', '4:203.0.113.42', 7200));
		$this->assertTrue($gate->isFirst('alice', '4:203.0.113.42', 7200), 'the same answer for the second asker of the request');
		$this->assertSame(1, $cache->adds);
		$this->assertFalse((new LoginGate($factory, $this->createMock(ISession::class)))->isFirst('alice', '4:203.0.113.42', 7300), 'the next request');
		$this->assertTrue((new LoginGate($factory, $this->createMock(ISession::class)))->isFirst('alice', '4:203.0.113.42', 10800), 'the next hour');
	}

	private function listener(Caches $factory, string $ip): LoginRecordListener {
		$addresses = $this->createMock(RemoteAddressResolver::class);
		$addresses->method('current')->willReturn(SourceKey::fromIp($ip));
		$addresses->method('isBypassListed')->willReturn(false);
		return new LoginRecordListener($this->appSettings(), Server::get(LoginMapper::class), $addresses, Server::get(ITimeFactory::class), Server::get(LoggerInterface::class), new LoginGate($factory, $this->createMock(ISession::class)));
	}

	private function lastId(): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->max('id'))->from(LoginMapper::TABLE);
		$result = $qb->executeQuery();
		$id = (int)$result->fetchOne();
		$result->closeCursor();
		return $id;
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
