<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Cache\CountBuffer;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\UserDailyMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\Privacy\UserDataCleanup;
use OCA\IntrusionDetection\Tests\Unit\Cache\ClockedCache;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IDBConnection;
use OCP\IMemcache;
use OCP\IUserManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\NullLogger;

/**
 * The failed logins of the user's security page (concept section 15.1):
 * counted per account and day, shown in the user's own days, with the
 * places they came from, at the cost of one read and one write per failure,
 * or per account and minute with a memory cache.
 */
#[Group('DB')]
class FailedLoginStatsTest extends LoginFailureTestCase {
	/** 2026-10-21 23:30 UTC, already the 22nd in Berlin */
	private const LATE = 1792625400;

	private int $now = self::LATE;
	private int $queries = 0;
	private bool $failNextReplace = false;
	/** How many optimistic updates in a row lose their race */
	private int $retriesFail = 1;
	private CountBuffer $buffer;
	private bool $failWrites = false;
	/** @var list<\Closure(): bool> */
	private array $owners = [];

	public function testFailuresOfExistingAccountsAreCountedFromTheFailedLoginPath(): void {
		$alice = $this->user('ids-fls-alice');
		$this->failLogin('203.0.113.5', $alice->getUID());
		$this->failLogin('203.0.113.6', $alice->getUID());
		$this->failLogin('203.0.113.7', 'nobody-has-this-name');

		$rows = $this->allRows(UserDailyMapper::TABLE);
		$this->assertCount(1, $rows, 'Login names without an account are not counted');
		$this->assertSame($alice->getUID(), $rows[0]['uid']);
		$this->assertSame(2, (int)$rows[0]['failed_logins']);
		$this->assertSame(2, Server::get(FailedLoginStats::class)->forUser($alice->getUID(), new \DateTimeZone('UTC'))['places']);
	}

	public function testNothingIsCountedWhileUsersDoNotHaveThePage(): void {
		$this->settingsEditor()->setGlobal(GlobalSettings::PERSONAL_PAGE_ENABLED, false);
		$alice = $this->user('ids-fls-off');
		$this->failLogin('203.0.113.5', $alice->getUID());
		$this->assertSame(0, $this->rows(UserDailyMapper::TABLE));
	}

	public function testOneReadAndOneWritePerFailureAndOneQueryForThePage(): void {
		$stats = $this->stats();
		$this->queries = 0;
		$stats->record('alice', SourceKey::fromIp('203.0.113.5'));
		$this->assertSame(2, $this->queries, 'The first failure of the day: a read and an insert');
		$this->queries = 0;
		$stats->record('alice', SourceKey::fromIp('203.0.113.6'));
		$this->assertSame(2, $this->queries, 'Every further one: a read and an update by the unique index');
		$this->queries = 0;
		$stats->forUser('alice', new \DateTimeZone('UTC'));
		$this->assertSame(1, $this->queries, 'The page reads at most 32 rows with one indexed query');
	}

	public function testWithAMemoryCacheAFailureCostsNoQueryAndAMinuteOneReadAndOneWrite(): void {
		$stats = $this->stats($this->cache());
		$this->now = self::LATE - 600;
		$this->queries = 0;
		foreach (['203.0.113.5', '203.0.113.6', '203.0.113.5', '2001:db8:1:2::7', '203.0.113.5'] as $i => $ip) {
			$this->now = self::LATE - 600 + $i;
			$stats->record('alice', SourceKey::fromIp($ip));
		}
		$stats->record('bob', SourceKey::fromIp('203.0.113.9'));
		$this->assertSame(0, $this->queries, 'The failures wait in the cache');
		$this->assertSame(0, $this->rows(UserDailyMapper::TABLE));

		$this->queries = 0;
		$page = $stats->forUser('alice', new \DateTimeZone('UTC'));
		$this->assertSame(1, $this->queries, 'The page reads its rows and adds what waits in the cache');
		$this->assertSame(5, $page['total']);
		$this->assertSame(3, $page['places']);
		$this->assertSame(['203.0.113.5', '2001:db8:1:2::/64', '203.0.113.6'], array_column($page['recent'], 'address'));

		$this->now = self::LATE - 600 + CountBuffer::PERIOD + CountBuffer::SETTLE;
		$this->queries = 0;
		$this->assertTrue($this->buffer->flush($this->owners));
		$this->assertSame(4, $this->queries, 'One read and one write per account and minute');
		$rows = array_column($this->allRows(UserDailyMapper::TABLE), null, 'uid');
		$this->assertSame(5, (int)$rows['alice']['failed_logins']);
		$this->assertSame(self::LATE - 596, (int)$rows['alice']['updated_at'], 'The time of the last failure');
		$this->assertSame(['203.0.113.6' => self::LATE - 599, '2001:db8:1:2::/64' => self::LATE - 597, '203.0.113.5' => self::LATE - 596], json_decode((string)$rows['alice']['sources'], true));
		$this->assertSame(1, (int)$rows['bob']['failed_logins']);

		$after = $stats->forUser('alice', new \DateTimeZone('UTC'));
		$this->assertSame($page['total'], $after['total'], 'Written once, and no longer counted from the cache');
		$this->assertSame($page['recent'], $after['recent']);
		$this->assertSame($page['days'], $after['days']);
	}

	public function testCountsOfTheCacheAreAddedToTheStoredDay(): void {
		$stats = $this->stats($this->cache());
		$this->now = self::LATE - 7200;
		$stats->record('alice', SourceKey::fromIp('203.0.113.5'));
		$this->now += CountBuffer::FLUSH_INTERVAL;
		$stats->record('alice', SourceKey::fromIp('203.0.113.6'));
		$this->assertTrue($this->buffer->flush($this->owners));
		$this->assertSame(1, (int)($this->allRows(UserDailyMapper::TABLE)[0]['failed_logins'] ?? 0), 'The settled minute is written, the current one waits');
		$this->now = self::LATE;
		$stats->record('alice', SourceKey::fromIp('203.0.113.7'));
		$this->assertTrue($this->buffer->flush($this->owners));
		$this->now += CountBuffer::PERIOD + CountBuffer::SETTLE;
		$this->assertTrue($this->buffer->flush($this->owners));
		$row = $this->allRows(UserDailyMapper::TABLE)[0];
		$this->assertSame(3, (int)$row['failed_logins']);
		$hours = json_decode((string)$row['hours'], true);
		$this->assertSame(2, $hours[21], '21:30 and 21:35');
		$this->assertSame(1, $hours[23]);
		$this->assertSame(3, $stats->forUser('alice', new \DateTimeZone('UTC'))['total']);
	}

	public function testAFlushThatRunsOutOfItsBudgetLeavesTheRestForTheNext(): void {
		$stats = $this->stats($this->cache());
		for ($i = 0; $i < 5; $i++) {
			$stats->record('user' . $i, SourceKey::fromIp('203.0.113.5'));
			$stats->record('user' . $i, SourceKey::fromIp('203.0.113.6'));
		}
		$this->now += CountBuffer::PERIOD + CountBuffer::SETTLE;
		$this->assertFalse($this->buffer->flush($this->owners, 3));
		$this->assertSame(3, $this->rows(UserDailyMapper::TABLE));
		$this->assertTrue($this->buffer->flush($this->owners, 3));
		$this->assertSame(10, array_sum(array_map(static fn (array $row): int => (int)$row['failed_logins'], $this->allRows(UserDailyMapper::TABLE))), 'Every failure, each once');
	}

	public function testAFailedWriteKeepsTheCountsForTheNextFlush(): void {
		$stats = $this->stats($this->cache());
		$stats->record('alice', SourceKey::fromIp('203.0.113.5'));
		$this->now += CountBuffer::PERIOD + CountBuffer::SETTLE;
		$this->failWrites = true;
		$this->assertFalse($this->buffer->flush($this->owners));
		$this->failWrites = false;
		$this->assertSame(0, $this->rows(UserDailyMapper::TABLE));
		$this->assertTrue($this->buffer->flush($this->owners));
		$this->assertSame(1, (int)$this->allRows(UserDailyMapper::TABLE)[0]['failed_logins']);
	}

	public function testDaysFollowTheUsersTimeZone(): void {
		$stats = $this->stats();
		$stats->record('alice', SourceKey::fromIp('203.0.113.5'));
		$this->now = self::LATE - 12 * 3600;
		$stats->record('alice', SourceKey::fromIp('203.0.113.5'));
		$this->now = self::LATE;

		$utc = $stats->forUser('alice', new \DateTimeZone('UTC'));
		$this->assertCount(FailedLoginStats::DAYS, $utc['days']);
		$this->assertSame(['day' => '2026-10-21', 'start' => 1792540800, 'count' => 2], $utc['days'][29], 'Both on the 21st in UTC');

		$berlin = $stats->forUser('alice', new \DateTimeZone('Europe/Berlin'));
		$this->assertSame('2026-10-22', $berlin['days'][29]['day']);
		$this->assertSame(1, $berlin['days'][29]['count'], '23:30 UTC is 01:30 on the 22nd in Berlin');
		$this->assertSame(1, $berlin['days'][28]['count']);
		$this->assertSame(2, $berlin['total']);
		$this->assertSame('Europe/Berlin', $berlin['timezone']);
	}

	public function testPlacesAreCountedAndTheMostRecentNamed(): void {
		$stats = $this->stats();
		foreach (['203.0.113.5', '203.0.113.6', '2001:db8:1:2::7', '203.0.113.5'] as $i => $ip) {
			$this->now = self::LATE - 3600 + $i * 60;
			$stats->record('alice', SourceKey::fromIp($ip));
		}
		$this->now = self::LATE;
		$result = $stats->forUser('alice', new \DateTimeZone('UTC'));
		$this->assertSame(3, $result['places']);
		$this->assertFalse($result['placesCapped']);
		$this->assertSame(['203.0.113.5', '2001:db8:1:2::/64', '203.0.113.6'], array_column($result['recent'], 'address'), 'Newest first; IPv6 by its /64');
	}

	public function testADayKeepsTwentyPlacesAndForgetsTheQuietestOne(): void {
		$stats = $this->stats();
		for ($i = 0; $i < FailedLoginStats::MAX_SOURCES + 3; $i++) {
			$this->now = self::LATE - 3600 + $i;
			$stats->record('alice', SourceKey::fromIp('198.51.100.' . ($i + 1)));
		}
		$this->now = self::LATE;
		$result = $stats->forUser('alice', new \DateTimeZone('UTC'));
		$this->assertSame(FailedLoginStats::MAX_SOURCES, $result['places']);
		$this->assertTrue($result['placesCapped'], 'The page says "at least"');
		$this->assertSame('198.51.100.23', $result['recent'][0]['address']);
		$this->assertSame(23, $result['total'], 'Every failure is counted, also beyond the places kept');
	}

	public function testAConcurrentFailureIsNeverLost(): void {
		$stats = $this->stats();
		$stats->record('alice', SourceKey::fromIp('203.0.113.5'));
		$this->failNextReplace = true;
		$stats->record('alice', SourceKey::fromIp('203.0.113.6'));
		$this->assertSame(3, $stats->forUser('alice', new \DateTimeZone('UTC'))['total'], 'The concurrent failure and this one, read again and written once more');

		$this->failNextReplace = true;
		$this->retriesFail = FailedLoginStats::RETRIES;
		$stats->record('alice', SourceKey::fromIp('203.0.113.6'));
		$result = $stats->forUser('alice', new \DateTimeZone('UTC'));
		$this->assertSame(3 + FailedLoginStats::RETRIES + 1, $result['total'], 'After the retries the count alone is raised');
		$this->assertSame($result['total'], $result['days'][29]['count'], 'Failures without their hour belong to the last one');
	}

	public function testOldDaysAndDeletedAccountsAreRemoved(): void {
		$stats = $this->stats();
		$this->now = self::LATE - (FailedLoginStats::RETENTION_DAYS + 1) * 86400;
		$stats->record('alice', SourceKey::fromIp('203.0.113.5'));
		$this->now = self::LATE;
		$stats->record('alice', SourceKey::fromIp('203.0.113.5'));
		$this->assertSame(1, $stats->purge($this->now));
		$this->assertSame(1, $this->rows(UserDailyMapper::TABLE));

		$bob = $this->user('ids-fls-bob');
		$stats->record($bob->getUID(), SourceKey::fromIp('203.0.113.5'));
		Server::get(UserDataCleanup::class)->deleteUser($bob->getUID());
		$this->assertSame(['alice'], array_column($this->allRows(UserDailyMapper::TABLE), 'uid'));
		Server::get(IUserManager::class)->get($bob->getUID())?->delete();
	}

	/**
	 * The stats with the test's clock, a connection that counts queries
	 * and can make the optimistic update lose a race, and optionally a
	 * memory cache.
	 */
	private function stats(?IMemcache $cache = null): FailedLoginStats {
		$real = Server::get(IDBConnection::class);
		$db = $this->createMock(IDBConnection::class);
		$db->method('getQueryBuilder')->willReturnCallback(function () use ($real) {
			$this->queries++;
			return $real->getQueryBuilder();
		});
		$db->method('insertIgnoreConflict')->willReturnCallback(function (string $table, array $values) use ($real): int {
			$this->queries++;
			if ($this->failWrites) {
				throw new \RuntimeException('The database is away');
			}
			return $real->insertIgnoreConflict($table, $values);
		});
		$mapper = new class($db, $this) extends UserDailyMapper {
			public function __construct(
				IDBConnection $db,
				private FailedLoginStatsTest $test,
			) {
				parent::__construct($db);
			}

			#[\Override]
			public function replace(string $uid, int $day, int $seen, int $count, string $hours, string $sources, int $now): bool {
				if ($this->test->loseRace()) {
					// Another request counted a failure in between.
					$this->increment($uid, $day, 1, $now);
				}
				return parent::replace($uid, $day, $seen, $count, $hours, $sources, $now);
			}
		};
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		$this->buffer = new CountBuffer($cache === null ? FixedCaches::none() : new FixedCaches($cache), $time, new NullLogger(), Server::get(Fingerprinter::class));
		$stats = new FailedLoginStats($mapper, $this->appSettings(), $time, $this->buffer);
		$this->owners = [$stats->writeCounts(...)];
		return $stats;
	}

	private function cache(): ClockedCache {
		return new ClockedCache(fn (): int => $this->now);
	}

	/**
	 * Whether the next optimistic update loses its race against a failure
	 * counted in between.
	 */
	public function loseRace(): bool {
		if (!$this->failNextReplace) {
			return false;
		}
		$this->retriesFail--;
		if ($this->retriesFail <= 0) {
			$this->failNextReplace = false;
			$this->retriesFail = 1;
		}
		return true;
	}
}
