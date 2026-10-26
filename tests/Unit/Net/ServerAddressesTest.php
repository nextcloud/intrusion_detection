<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Net;

use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\State\AppState;
use OCA\IntrusionDetection\Tests\Unit\Cache\ClockedCache;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IMemcache;
use Test\TestCase;

class ServerAddressesTest extends TestCase {
	private const NOW = 1792625400;

	private int $now = self::NOW;
	/** @var array<string, string> the ids_state rows by name */
	private array $rows = [];
	private int $reads = 0;
	private int $writes = 0;
	/** A cache per web server */
	private ClockedCache $local;

	protected function setUp(): void {
		parent::setUp();
		$this->local = new ClockedCache(fn (): int => $this->now);
	}

	protected function tearDown(): void {
		unset($_SERVER['SERVER_ADDR']);
		parent::tearDown();
	}

	public function testANewAddressIsStoredOnceAndKnownWithoutAWebRequest(): void {
		$servers = $this->servers();
		$_SERVER['SERVER_ADDR'] = '192.0.2.10';
		$servers->observe();
		$servers->observe();
		$this->assertSame(1, $this->writes, 'Written only when it is new');
		$this->assertSame(1, $this->reads, 'Then remembered in the cache');
		unset($_SERVER['SERVER_ADDR']);
		$this->assertTrue($servers->contains(SourceKey::fromIp('192.0.2.10')));
		$this->assertFalse($servers->contains(SourceKey::fromIp('192.0.2.11')));
	}

	public function testManyWebServersDoNotPushEachOtherOut(): void {
		$caches = [];
		for ($round = 0; $round < 3; $round++) {
			for ($i = 1; $i <= 40; $i++) {
				$_SERVER['SERVER_ADDR'] = '2001:db8::' . dechex($i);
				$caches[$i] ??= new ClockedCache(fn (): int => $this->now);
				$this->servers($caches[$i])->observe();
			}
		}
		$this->assertSame(40, $this->writes, 'Each of 40 web servers wrote its address once');
		$this->assertSame(40, $this->reads, 'and read it once');
		unset($_SERVER['SERVER_ADDR']);
		$this->assertCount(40, $this->servers()->all());
	}

	public function testTheRowIsRefreshedOnceADayAndForgottenWhenQuiet(): void {
		$_SERVER['SERVER_ADDR'] = '192.0.2.10';
		$this->servers()->observe();
		$this->now += ServerAddresses::SEEN_TTL;
		$this->servers()->observe();
		$this->assertSame(1, $this->writes, 'A known address is read again after an hour, not written');
		$this->assertSame(2, $this->reads);
		$this->now = self::NOW + ServerAddresses::REFRESH;
		$this->servers()->observe();
		$this->assertSame(2, $this->writes, 'and written again after a day');

		$_SERVER['SERVER_ADDR'] = '192.0.2.11';
		$this->now += ServerAddresses::RETENTION + 1;
		$this->servers()->observe();
		$this->assertSame(['server_address/192.0.2.11'], array_keys($this->rows), 'Writing the new address forgot the quiet one');
	}

	public function testOnlyTheLatestAreKept(): void {
		for ($i = 0; $i < ServerAddresses::MAX_REMEMBERED + 3; $i++) {
			$this->rows[ServerAddresses::STATE_PREFIX . '10.0.' . intdiv($i, 250) . '.' . ($i % 250 + 1)] = (string)(self::NOW + $i);
		}
		$this->assertCount(ServerAddresses::MAX_REMEMBERED, $this->servers()->all());
		$this->assertSame(3, $this->servers()->forget($this->now));
		$this->assertArrayNotHasKey(ServerAddresses::STATE_PREFIX . '10.0.0.1', $this->rows);
	}

	public function testTheAddressOfTheRequestCountsBeforeItIsStored(): void {
		$_SERVER['SERVER_ADDR'] = '192.0.2.10';
		$this->assertTrue($this->servers()->contains(SourceKey::fromIp('192.0.2.10')));
		$this->assertSame(0, $this->writes);
	}

	public function testWithoutAWebRequestNothingIsStored(): void {
		$this->servers()->observe();
		$this->assertSame(0, $this->writes);
		$this->assertSame(0, $this->reads);
	}

	public function testWithoutAMemoryCacheEachObservationReadsOnce(): void {
		$_SERVER['SERVER_ADDR'] = '192.0.2.10';
		$servers = new ServerAddresses($this->state(), FixedCaches::none(), $this->time());
		$servers->observe();
		$servers->observe();
		$this->assertSame(1, $this->writes);
		$this->assertSame(2, $this->reads);
	}

	private function servers(?IMemcache $local = null): ServerAddresses {
		return new ServerAddresses($this->state(), new FixedCaches(null, $local ?? $this->local), $this->time());
	}

	private function state(): AppState {
		$state = $this->createMock(AppState::class);
		$state->method('getInt')->willReturnCallback(function (string $name): int {
			$this->reads++;
			return (int)($this->rows[$name] ?? 0);
		});
		$state->method('setInt')->willReturnCallback(function (string $name, int $value): void {
			$this->writes++;
			$this->rows[$name] = (string)$value;
		});
		$state->method('getPrefixed')->willReturnCallback(function (string $prefix): array {
			$found = [];
			foreach ($this->rows as $name => $value) {
				if (str_starts_with($name, $prefix)) {
					$found[substr($name, strlen($prefix))] = $value;
				}
			}
			return $found;
		});
		$state->method('deleteNames')->willReturnCallback(function (array $names): int {
			$deleted = count(array_intersect_key($this->rows, array_flip($names)));
			$this->rows = array_diff_key($this->rows, array_flip($names));
			return $deleted;
		});
		return $state;
	}

	private function time(): ITimeFactory {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		return $time;
	}
}
