<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Notification;

use OCA\IntrusionDetection\Notification\DigestSchedule;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class DigestScheduleTest extends TestCase {
	/**
	 * @return array<string, array{string, string, string, string, string}>
	 */
	public static function dueTimes(): array {
		return [
			'weekly, Wednesday' => ['weekly', 'Europe/Berlin', '2026-10-21 10:00', '2026-10-19 08:00', '2026-10-26 08:00'],
			'weekly, exactly Monday 08:00' => ['weekly', 'Europe/Berlin', '2026-10-19 08:00', '2026-10-19 08:00', '2026-10-26 08:00'],
			'weekly, Monday 07:59' => ['weekly', 'Europe/Berlin', '2026-10-19 07:59', '2026-10-12 08:00', '2026-10-19 08:00'],
			'weekly, Sunday night' => ['weekly', 'Europe/Berlin', '2026-10-25 23:59', '2026-10-19 08:00', '2026-10-26 08:00'],
			'weekly, across the end of summer time' => ['weekly', 'Europe/Berlin', '2026-10-26 09:00', '2026-10-26 08:00', '2026-11-02 08:00'],
			'weekly, half-hour zone' => ['weekly', 'Asia/Kolkata', '2026-10-19 08:30', '2026-10-19 08:00', '2026-10-26 08:00'],
			'weekly, local Monday is UTC Sunday' => ['weekly', 'Pacific/Auckland', '2026-09-28 08:00', '2026-09-28 08:00', '2026-10-05 08:00'],
			'weekly, UTC' => ['weekly', 'UTC', '2026-10-20 12:00', '2026-10-19 08:00', '2026-10-26 08:00'],
			'daily, afternoon' => ['daily', 'America/New_York', '2026-10-20 15:00', '2026-10-20 08:00', '2026-10-21 08:00'],
			'daily, early morning' => ['daily', 'America/New_York', '2026-10-20 07:00', '2026-10-19 08:00', '2026-10-20 08:00'],
			'daily, day summer time starts' => ['daily', 'America/New_York', '2026-03-08 09:00', '2026-03-08 08:00', '2026-03-09 08:00'],
			'daily, day summer time ends' => ['daily', 'Europe/Berlin', '2026-10-25 08:00', '2026-10-25 08:00', '2026-10-26 08:00'],
		];
	}

	#[DataProvider('dueTimes')]
	public function testDueTimesAreAt0800LocalTime(string $frequency, string $zone, string $now, string $lastDue, string $nextDue): void {
		$timezone = new \DateTimeZone($zone);
		$schedule = new DigestSchedule($frequency, $timezone);
		$at = self::at($now, $timezone);
		$this->assertSame(self::at($lastDue, $timezone), $schedule->lastDue($at), 'last due');
		$this->assertSame(self::at($nextDue, $timezone), $schedule->nextDue($at), 'next due');
	}

	public function testAWeekIsAWeekOnTheWallClockAcrossDaylightSavingChanges(): void {
		$berlin = new \DateTimeZone('Europe/Berlin');
		$schedule = new DigestSchedule(DigestSchedule::WEEKLY, $berlin);
		// Summer time ends on 25 October 2026: that week has an hour more.
		[$start, $end] = $schedule->periodEndingAt(self::at('2026-10-26 08:00', $berlin));
		$this->assertSame(self::at('2026-10-19 08:00', $berlin), $start);
		$this->assertSame(7 * 86400 + 3600, $end - $start);
		// And the week it starts has an hour less.
		[$start, $end] = $schedule->periodEndingAt(self::at('2026-03-30 08:00', $berlin));
		$this->assertSame(7 * 86400 - 3600, $end - $start);

		$auckland = new \DateTimeZone('Pacific/Auckland');
		[$start, $end] = (new DigestSchedule(DigestSchedule::WEEKLY, $auckland))->periodEndingAt(self::at('2026-09-28 08:00', $auckland));
		$this->assertSame(self::at('2026-09-21 08:00', $auckland), $start);
		$this->assertSame(7 * 86400 - 3600, $end - $start);
	}

	public function testADayIsADayOnTheWallClock(): void {
		$newYork = new \DateTimeZone('America/New_York');
		$schedule = new DigestSchedule(DigestSchedule::DAILY, $newYork);
		[$start, $end] = $schedule->periodEndingAt(self::at('2026-03-08 08:00', $newYork));
		$this->assertSame(self::at('2026-03-07 08:00', $newYork), $start);
		$this->assertSame(23 * 3600, $end - $start);
		[$start, $end] = $schedule->periodEndingAt(self::at('2026-10-20 08:00', $newYork));
		$this->assertSame(86400, $end - $start);
		$this->assertSame(DigestSchedule::DAILY, $schedule->periodKind());
	}

	public function testOffHasNoDueTimesAndAWeekAsTestPeriod(): void {
		foreach ([DigestSchedule::OFF, 'monthly', ''] as $frequency) {
			$schedule = new DigestSchedule($frequency, new \DateTimeZone('UTC'));
			$this->assertTrue($schedule->isOff(), $frequency);
			$this->assertNull($schedule->lastDue(1_800_000_000));
			$this->assertNull($schedule->nextDue(1_800_000_000));
			$this->assertSame([1_800_000_000 - 7 * 86400, 1_800_000_000], $schedule->periodEndingAt(1_800_000_000));
			$this->assertSame(DigestSchedule::WEEKLY, $schedule->periodKind());
		}
	}

	public function testADigestIsSentAtMostTwelveHoursLate(): void {
		$schedule = new DigestSchedule(DigestSchedule::WEEKLY, new \DateTimeZone('UTC'));
		$due = 1_800_000_000;
		$this->assertTrue($schedule->isWithinGrace($due, $due));
		$this->assertTrue($schedule->isWithinGrace($due, $due + DigestSchedule::GRACE));
		$this->assertFalse($schedule->isWithinGrace($due, $due + DigestSchedule::GRACE + 1));
		$this->assertFalse($schedule->isWithinGrace($due, $due - 1));
	}

	private static function at(string $local, \DateTimeZone $timezone): int {
		return (new \DateTimeImmutable($local, $timezone))->getTimestamp();
	}
}
