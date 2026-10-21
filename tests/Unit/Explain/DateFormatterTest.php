<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Explain;

use OCA\IntrusionDetection\Explain\DateFormatter;
use OCP\IDateTimeFormatter;
use OCP\IL10N;
use Test\TestCase;

class DateFormatterTest extends TestCase {
	/** @var list<array{string, ?string, ?IL10N}> */
	private array $calls = [];
	private DateFormatter $dates;

	protected function setUp(): void {
		parent::setUp();
		$formatter = $this->createMock(IDateTimeFormatter::class);
		$formatter->method('formatDateTime')->willReturnCallback(function (int $ts, string $date, string $time, ?\DateTimeZone $tz = null, ?IL10N $l = null): string {
			$this->calls[] = ['dateTime', $tz?->getName(), $l];
			return 'formatted';
		});
		$formatter->method('formatTime')->willReturnCallback(function (int $ts, string $format, ?\DateTimeZone $tz = null, ?IL10N $l = null): string {
			$this->calls[] = ['time', $tz?->getName(), $l];
			return 'formatted';
		});
		$formatter->method('formatTimeSpan')->willReturnCallback(function (int $ts, ?int $base = null, ?IL10N $l = null): string {
			$this->calls[] = ['ago', null, $l];
			return 'formatted';
		});
		$this->dates = DateFormatter::using($formatter);
	}

	public function testOutsideAReaderScopeTheSessionsTimeZoneAndLanguageAreUsed(): void {
		$this->dates->dateTime(0);
		$this->dates->time(0);
		$this->assertSame([['dateTime', null, null], ['time', null, null]], $this->calls);
	}

	public function testEveryTimeWithinAReaderScopeIsInTheReadersTimeZoneAndLanguage(): void {
		$l = $this->createMock(IL10N::class);
		$this->dates->forReader(new \DateTimeZone('Asia/Tokyo'), $l, function (): void {
			$this->dates->dateTime(0);
			$this->dates->time(0);
			$this->dates->ago(0, 60);
		});
		$this->assertSame([['dateTime', 'Asia/Tokyo', $l], ['time', 'Asia/Tokyo', $l], ['ago', null, $l]], $this->calls);
	}

	public function testScopesNestAndEndAlsoWhenTheBuildFails(): void {
		$tokyo = $this->createMock(IL10N::class);
		$berlin = $this->createMock(IL10N::class);
		$result = $this->dates->forReader(new \DateTimeZone('Asia/Tokyo'), $tokyo, function () use ($berlin): string {
			try {
				$this->dates->forReader(new \DateTimeZone('Europe/Berlin'), $berlin, function (): never {
					$this->dates->dateTime(0);
					throw new \RuntimeException('failed');
				});
			} catch (\RuntimeException) {
			}
			$this->dates->dateTime(0);
			return 'built';
		});
		$this->dates->dateTime(0);

		$this->assertSame('built', $result);
		$this->assertSame([['dateTime', 'Europe/Berlin', $berlin], ['dateTime', 'Asia/Tokyo', $tokyo], ['dateTime', null, null]], $this->calls);
	}
}
