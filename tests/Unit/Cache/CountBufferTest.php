<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Cache;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Cache\CountBuffer;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use Psr\Log\NullLogger;
use Test\TestCase;

class CountBufferTest extends TestCase {
	/** A minute start */
	private const T0 = 1792625400;

	private int $now = self::T0;
	private ClockedCache $cache;
	private CountBuffer $buffer;
	/** @var list<array{0: string, 1: array{start: int, count: int, last: int, details: array<string, int>}}> */
	private array $written = [];
	private bool $failWrites = false;
	/** @var list<\Closure(): bool> the writers of the owners */
	private array $owners = [];

	protected function setUp(): void {
		parent::setUp();
		$this->cache = new ClockedCache(fn (): int => $this->now);
		$this->buffer = $this->buffer(new FixedCaches($this->cache));
	}

	public function testWithoutACacheOrWithOneThatEndsWithTheRequestNothingIsCounted(): void {
		$this->assertFalse($this->buffer(FixedCaches::none())->count('t', 'alice'));
		$this->assertFalse($this->buffer(new FixedCaches(new ArrayCache()))->count('t', 'alice'), 'core\'s ArrayCache forgets it at the end of the request');
	}

	public function testAMinuteIsWrittenOnceItSettledAndThenRemoved(): void {
		$this->assertTrue($this->buffer->count('t', 'alice', '203.0.113.5'));
		$this->now += 5;
		$this->buffer->count('t', 'alice', '203.0.113.6');
		$this->now++;
		$this->buffer->count('t', 'alice', '203.0.113.5');
		$this->buffer->count('t', 'bob');

		$this->now = self::T0 + CountBuffer::PERIOD + CountBuffer::SETTLE - 1;
		$this->assertTrue($this->buffer->flush($this->owners));
		$this->assertSame([], $this->written, 'Not before the minute settled');

		$this->now++;
		$this->assertTrue($this->buffer->flush($this->owners));
		$this->assertSame([
			['alice', ['start' => self::T0, 'count' => 3, 'last' => self::T0 + 6, 'details' => ['203.0.113.6' => self::T0 + 5, '203.0.113.5' => self::T0 + 6]]],
			['bob', ['start' => self::T0, 'count' => 1, 'last' => self::T0 + 6, 'details' => []]],
		], $this->written);

		$this->written = [];
		$this->assertTrue($this->buffer->flush($this->owners));
		$this->assertSame([], $this->written, 'Each minute is written once');
		$this->assertSame(1, $this->cache->size(), 'Only the cursor is left');
	}

	public function testAMemberKeepsTheLatestDetailsAndEveryCount(): void {
		for ($i = 1; $i <= CountBuffer::MAX_DETAILS + 5; $i++) {
			$this->buffer->count('t', 'list', '198.51.100.' . $i);
		}
		$this->now += CountBuffer::PERIOD + CountBuffer::SETTLE;
		$this->buffer->flush($this->owners);
		$this->assertSame(CountBuffer::MAX_DETAILS + 5, $this->written[0][1]['count']);
		$this->assertCount(CountBuffer::MAX_DETAILS, $this->written[0][1]['details']);
		$this->assertArrayHasKey('198.51.100.25', $this->written[0][1]['details']);
		$this->assertArrayNotHasKey('198.51.100.5', $this->written[0][1]['details']);
	}

	public function testPendingCountsAreReadUntilTheyAreWritten(): void {
		$this->buffer->count('t', 'alice', '203.0.113.5');
		$this->now += CountBuffer::PERIOD;
		$this->buffer->count('t', 'alice', '203.0.113.5');
		$this->buffer->count('t', 'bob');
		$pending = $this->buffer->pending('t', 'alice');
		$this->assertSame([self::T0, self::T0 + CountBuffer::PERIOD], array_column($pending, 'start'));
		$this->assertSame([1, 1], array_column($pending, 'count'));

		$this->now += CountBuffer::SETTLE;
		$this->buffer->flush($this->owners);
		$this->assertSame([self::T0 + CountBuffer::PERIOD], array_column($this->buffer->pending('t', 'alice'), 'start'), 'The written minute is no longer pending');
	}

	public function testATakenCountIsNotWrittenAgain(): void {
		$this->buffer->count('t', 'alice');
		$this->now += 3;
		$this->buffer->count('t', 'alice');
		$this->buffer->count('t', 'bob');
		$this->assertSame([2, self::T0 + 3], $this->buffer->take('t', 'alice'));
		$this->assertSame([0, 0], $this->buffer->take('t', 'alice'));
		$this->now += CountBuffer::PERIOD + CountBuffer::SETTLE;
		$this->buffer->flush($this->owners);
		$this->assertSame(['bob'], array_column($this->written, 0));
	}

	public function testAWebRequestFlushesOncePerIntervalAndContinuesABacklog(): void {
		for ($i = 0; $i < CountBuffer::REQUEST_BUDGET + 5; $i++) {
			$this->buffer->count('t', 'user' . $i);
		}
		$this->now += CountBuffer::PERIOD + CountBuffer::SETTLE;
		$this->buffer->flushIfDue(fn (): array => $this->owners);
		$this->assertCount(CountBuffer::REQUEST_BUDGET, $this->written);
		$this->buffer->flushIfDue(fn (): array => $this->owners);
		$this->assertCount(CountBuffer::REQUEST_BUDGET + 5, $this->written, 'A flush that ran out of budget leaves the next request due');

		$this->buffer->count('t', 'late');
		$this->now += CountBuffer::PERIOD + CountBuffer::SETTLE;
		$this->buffer->flushIfDue(fn (): array => $this->owners);
		$this->assertCount(CountBuffer::REQUEST_BUDGET + 5, $this->written, 'Then not again within the interval');
		$this->now += CountBuffer::FLUSH_INTERVAL;
		$this->buffer->flushIfDue(fn (): array => $this->owners);
		$this->assertSame('late', $this->written[CountBuffer::REQUEST_BUDGET + 5][0]);
	}

	public function testOnlyOneFlushRunsAtATime(): void {
		$this->buffer->count('t', 'alice');
		$this->now += CountBuffer::PERIOD + CountBuffer::SETTLE;
		$this->cache->add('lock', 1, 120);
		$this->assertTrue($this->buffer->flush($this->owners));
		$this->assertSame([], $this->written);
		$this->cache->remove('lock');
		$this->buffer->flush($this->owners);
		$this->assertCount(1, $this->written);
	}

	public function testAFailedWriteKeepsTheMemberAndNothingIsWrittenTwice(): void {
		$this->buffer->count('t', 'alice');
		$this->buffer->count('t', 'bob');
		$this->now += CountBuffer::PERIOD + CountBuffer::SETTLE;
		$this->failWrites = true;
		$this->assertFalse($this->buffer->flush($this->owners));
		$this->failWrites = false;
		$this->assertSame(['alice'], array_column($this->written, 0), 'Alice was written before Bob failed');
		$this->assertTrue($this->buffer->flush($this->owners));
		$this->assertSame(['alice', 'bob'], array_column($this->written, 0));
	}

	private function buffer(FixedCaches $caches): CountBuffer {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturn('a-test-secret');
		$buffer = new CountBuffer($caches, $time, new NullLogger(), new Fingerprinter($config, $time));
		$this->owners = [fn (): bool => $buffer->drain('t', fn (string $member, array $pending) => $this->write($member, $pending))];
		return $buffer;
	}

	/**
	 * @param array{start: int, count: int, last: int, details: array<string, int>} $pending
	 */
	public function write(string $member, array $pending): void {
		if ($this->failWrites && $this->written !== []) {
			throw new \RuntimeException('The database is away');
		}
		$this->written[] = [$member, $pending];
	}
}
