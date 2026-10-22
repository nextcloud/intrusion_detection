<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Login;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Login\LoginGate;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\ISession;
use Test\TestCase;

class LoginGateTest extends TestCase {
	private const HOUR = 1_792_501_200;

	/** @var list<string> operations on the distributed cache */
	private array $remote = [];
	private ArrayCache $shared;
	private ?int $tokenId = 7;

	protected function setUp(): void {
		parent::setUp();
		$remote = &$this->remote;
		$this->shared = new class($remote) extends ArrayCache {
			/** @param list<string> $ops */
			public function __construct(
				private array &$ops,
			) {
				parent::__construct();
			}

			public function get($key) {
				$this->ops[] = 'get';
				return parent::get($key);
			}

			public function add($key, $value, $ttl = 0) {
				$this->ops[] = 'add';
				return parent::add($key, $value, $ttl);
			}
		};
	}

	/**
	 * A gate as one request of one web server sees it.
	 */
	private function gate(ArrayCache $local, bool $distributed = true): LoginGate {
		$caches = $distributed ? new FixedCaches($this->shared, $local, true) : new FixedCaches($local, $local);
		$session = $this->createMock(ISession::class);
		$session->method('get')->willReturnCallback(fn (string $key): ?int => $key === 'token-id' ? $this->tokenId : null);
		return new LoginGate($caches, $session);
	}

	public function testOneDistributedRoundTripPerCredentialAddressAndHourOnEachServer(): void {
		$serverA = new ArrayCache();
		$serverB = new ArrayCache();

		$first = $this->gate($serverA);
		$this->assertTrue($first->isFirst('alice', '4:203.0.113.5', self::HOUR + 10));
		$this->assertTrue($first->isFirst('alice', '4:203.0.113.5', self::HOUR + 10), 'the history asks after the logins per address');
		$this->assertSame(['add'], $this->remote, 'one round trip for both');

		$this->remote = [];
		for ($i = 0; $i < 3; $i++) {
			$this->assertFalse($this->gate($serverA)->isFirst('alice', '4:203.0.113.5', self::HOUR + 100 + $i));
		}
		$this->assertSame([], $this->remote, 'later requests on the same server ask only its local cache');

		$this->assertFalse($this->gate($serverB)->isFirst('alice', '4:203.0.113.5', self::HOUR + 200), 'another server knows it from the distributed cache');
		$this->assertSame(['add'], $this->remote);
	}

	public function testTheCredentialTheAddressAndTheHourEachOpenTheGate(): void {
		$local = new ArrayCache();
		$this->assertTrue($this->gate($local)->isFirst('alice', '4:203.0.113.5', self::HOUR));
		$this->tokenId = 8;
		$this->assertTrue($this->gate($local)->isFirst('alice', '4:203.0.113.5', self::HOUR), 'another app password');
		$this->tokenId = null;
		$this->assertTrue($this->gate($local)->isFirst('alice', '4:203.0.113.5', self::HOUR), 'the password');
		$this->assertTrue($this->gate($local)->isFirst('alice', '4:203.0.113.6', self::HOUR), 'another address');
		$this->assertTrue($this->gate($local)->isFirst('bob', '4:203.0.113.6', self::HOUR), 'another account');
		$this->assertTrue($this->gate($local)->isFirst('alice', '4:203.0.113.6', self::HOUR + 3600), 'the next hour');
		$this->assertFalse($this->gate($local)->isFirst('alice', '4:203.0.113.6', self::HOUR + 3599));
	}

	public function testALocalCacheAloneIsTheGate(): void {
		$local = new ArrayCache();
		$this->assertTrue($this->gate($local, false)->isFirst('alice', '4:203.0.113.5', self::HOUR));
		$this->assertFalse($this->gate($local, false)->isFirst('alice', '4:203.0.113.5', self::HOUR + 5));
		$this->assertSame([], $this->remote);
	}

	public function testWithoutAMemoryCacheItCannotTell(): void {
		$gate = new LoginGate(FixedCaches::none(), $this->createMock(ISession::class));
		$this->assertNull($gate->isFirst('alice', '4:203.0.113.5', self::HOUR));
	}
}
