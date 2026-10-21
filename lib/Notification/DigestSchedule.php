<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

/**
 * When the admin digest is due, and which period it covers.
 *
 * Weekly digests are due on Monday at 08:00, daily ones every day at 08:00,
 * both in the server's default time zone. A period ends when its digest is
 * due and starts one week (or day) earlier on the wall clock, so across a
 * daylight saving change it is an hour longer or shorter.
 */
final class DigestSchedule {
	public const OFF = 'off';
	public const DAILY = 'daily';
	public const WEEKLY = 'weekly';
	public const FREQUENCIES = [self::OFF, self::DAILY, self::WEEKLY];

	public const HOUR = 8;
	/**
	 * A digest is sent at most this long after it was due. When cron did not
	 * run in time, that digest is skipped rather than sent days late.
	 */
	public const GRACE = 12 * 3600;

	public function __construct(
		public readonly string $frequency,
		public readonly \DateTimeZone $timezone,
	) {
	}

	public function isOff(): bool {
		return $this->frequency !== self::DAILY && $this->frequency !== self::WEEKLY;
	}

	/**
	 * The most recent time a digest was due, at or before `$now`; null when off.
	 */
	public function lastDue(int $now): ?int {
		if ($this->isOff()) {
			return null;
		}
		$due = $this->local($now)->setTime(self::HOUR, 0);
		if ($this->frequency === self::WEEKLY) {
			$due = $due->modify('-' . ((int)$due->format('N') - 1) . ' days')->setTime(self::HOUR, 0);
		}
		if ($due->getTimestamp() > $now) {
			$due = $this->step($due, -1);
		}
		return $due->getTimestamp();
	}

	/**
	 * The next time a digest is due, after `$now`; null when off.
	 */
	public function nextDue(int $now): ?int {
		$last = $this->lastDue($now);
		return $last === null ? null : $this->step($this->local($last), 1)->getTimestamp();
	}

	/**
	 * Whether the digest due at `$due` may still be sent at `$now`.
	 */
	public function isWithinGrace(int $due, int $now): bool {
		return $now >= $due && $now - $due <= self::GRACE;
	}

	/**
	 * The period that ends at `$end`: one week (or day) on the wall clock.
	 * For a schedule that is off, a week.
	 *
	 * @return array{0: int, 1: int} start (inclusive) and end (exclusive)
	 */
	public function periodEndingAt(int $end): array {
		return [$this->step($this->local($end), -1)->getTimestamp(), $end];
	}

	/**
	 * @return 'daily'|'weekly'
	 */
	public function periodKind(): string {
		return $this->frequency === self::DAILY ? self::DAILY : self::WEEKLY;
	}

	private function local(int $timestamp): \DateTimeImmutable {
		return (new \DateTimeImmutable('@' . $timestamp))->setTimezone($this->timezone);
	}

	/**
	 * One period forward or back, keeping the wall-clock time.
	 */
	private function step(\DateTimeImmutable $time, int $direction): \DateTimeImmutable {
		$days = $this->periodKind() === self::DAILY ? 1 : 7;
		$moved = $time->modify(($direction < 0 ? '-' : '+') . $days . ' days');
		return $moved->setTime((int)$time->format('G'), (int)$time->format('i'), (int)$time->format('s'));
	}
}
