<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Personal;

use OCA\IntrusionDetection\Cache\CountBuffer;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Db\IPurges;
use OCA\IntrusionDetection\Db\UserDailyMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * The failed logins to an account over the last 30 days, for the user's own
 * security page (concept section 15.1).
 *
 * Failed attempts themselves are kept for one hour only, so each failure
 * of an existing account also counts into one row per account and UTC day
 * (ids_user_daily): a count per hour, so that the page can show the user's
 * own days, and up to MAX_SOURCES addresses with their last failure.
 *
 * A failure is counted in the memory cache ({@see CountBuffer}), so that an
 * attack on one account does not rewrite its row from every web server; the
 * counts of each minute are written with one read and one write by the
 * unique index. The page adds what still waits in the cache. Without a
 * memory cache each failure is written this way. Concurrent writes are
 * detected with the count read; after RETRIES attempts the count alone is
 * raised, and the page attributes the remainder to the hour of the last
 * failure.
 *
 * @psalm-import-type IntrusionDetectionFailedLogins from ResponseDefinitions
 * @psalm-import-type PendingCount from CountBuffer
 * @psalm-type DayRow = array{day: int, count: int, hours: list<int>, sources: array<string, int>, updatedAt: int}
 */
class FailedLoginStats implements IPurges {
	public const DAYS = 30;
	/** Rows are kept a little longer than shown, for the time zone shift */
	public const RETENTION_DAYS = self::DAYS + 1;
	public const MAX_SOURCES = 20;
	/** The most recent addresses shown */
	public const RECENT = 5;
	public const RETRIES = 3;
	/** The name of the counts in {@see CountBuffer} */
	public const BUFFER = 'failed';
	private const DAY = 86400;

	public function __construct(
		private readonly UserDailyMapper $mapper,
		private readonly AppSettings $settings,
		private readonly ITimeFactory $timeFactory,
		private readonly CountBuffer $buffer,
	) {
	}

	/**
	 * Delete the days older than RETENTION_DAYS.
	 */
	#[\Override]
	public function purge(int $now): int {
		$today = intdiv($now, self::DAY) * self::DAY;
		return $this->mapper->deleteBefore($today - self::RETENTION_DAYS * self::DAY);
	}

	/**
	 * Whether failures are counted: only while users have the page.
	 */
	public function isEnabled(): bool {
		return $this->settings->personalPageSwitchedOn();
	}

	/**
	 * Count one failed login to an existing account.
	 */
	public function record(string $uid, SourceKey $source): void {
		if ($this->buffer->count(self::BUFFER, $uid, $source->ipKey)) {
			return;
		}
		$now = $this->timeFactory->getTime();
		$this->write($uid, $now, 1, [$source->ipKey => $now], $now);
	}

	/**
	 * Write the failures that wait in the memory cache.
	 *
	 * @return bool false when some were left for a later flush
	 */
	public function writeCounts(): bool {
		return $this->buffer->drain(self::BUFFER, function (string $uid, array $pending): void {
			$this->write($uid, $pending['start'], $pending['count'], $pending['details'], $pending['last']);
		});
	}

	/**
	 * Add failures of one hour to the account's row of that day.
	 *
	 * @param int $at a time in the hour
	 * @param array<string, int> $sources address key => last failure
	 * @param int $last the time of the last of these failures
	 */
	private function write(string $uid, int $at, int $count, array $sources, int $last): void {
		$day = intdiv($at, self::DAY) * self::DAY;
		$hour = intdiv($at - $day, 3600);
		for ($i = 0; $i < self::RETRIES; $i++) {
			$row = $this->mapper->find($uid, $day);
			if ($row === null) {
				$hours = array_fill(0, 24, 0);
				$hours[$hour] = $count;
				if ($this->mapper->insert($uid, $day, $count, self::encode($hours), self::encode(self::withSources([], $sources)), $last)) {
					return;
				}
				continue;
			}
			$hours = self::hours($row['hours']);
			$hours[$hour] += $count;
			$merged = self::withSources(self::sources($row['sources']), $sources);
			if ($this->mapper->replace($uid, $day, $row['failed_logins'], $count, self::encode($hours), self::encode($merged), max($last, $row['updated_at']))) {
				return;
			}
		}
		$this->mapper->increment($uid, $day, $count, $last);
	}

	/**
	 * The last DAYS days in the time zone, today last.
	 *
	 * @return IntrusionDetectionFailedLogins
	 */
	public function forUser(string $uid, \DateTimeZone $timeZone): array {
		[$days, $sources, $capped] = $this->collect($uid, $timeZone);
		arsort($sources);
		$recent = [];
		foreach (array_slice($sources, 0, self::RECENT, true) as $address => $lastSeen) {
			$recent[] = ['address' => (string)$address, 'lastSeenAt' => $lastSeen];
		}
		$list = [];
		$total = 0;
		foreach ($days as $day) {
			$list[] = ['day' => $day['day'], 'start' => $day['start'], 'count' => $day['count']];
			$total += $day['count'];
		}
		return [
			'days' => $list,
			'total' => $total,
			'places' => count($sources),
			'placesCapped' => $capped,
			'recent' => $recent,
			'timezone' => $timeZone->getName(),
		];
	}

	/**
	 * The days of the last DAYS days in the time zone that had failed
	 * logins, newest first, with about when the last one failed: the time
	 * of the last failure of a UTC day, or the end of an earlier hour.
	 *
	 * @return list<array{day: string, count: int, lastAt: int}>
	 */
	public function daysWithFailures(string $uid, \DateTimeZone $timeZone): array {
		[$days] = $this->collect($uid, $timeZone);
		$list = [];
		foreach (array_reverse($days) as $day) {
			if ($day['count'] > 0) {
				$list[] = ['day' => $day['day'], 'count' => $day['count'], 'lastAt' => $day['lastAt']];
			}
		}
		return $list;
	}

	/**
	 * One read of the rows of the last DAYS days.
	 *
	 * @return array{0: list<array{day: string, start: int, count: int, lastAt: int}>, 1: array<string, int>, 2: bool} the days oldest first, the addresses with their last failure, and whether a day had more addresses than kept
	 */
	private function collect(string $uid, \DateTimeZone $timeZone): array {
		$now = $this->timeFactory->getTime();
		$midnight = (new \DateTimeImmutable('@' . $now))->setTimezone($timeZone)->setTime(0, 0);
		/** @var array<string, array{day: string, start: int, count: int, lastAt: int}> $days */
		$days = [];
		for ($i = self::DAYS - 1; $i >= 0; $i--) {
			$start = $midnight->modify('-' . $i . ' days');
			$days[$start->format('Y-m-d')] = ['day' => $start->format('Y-m-d'), 'start' => $start->getTimestamp(), 'count' => 0, 'lastAt' => 0];
		}
		$first = $midnight->modify('-' . (self::DAYS - 1) . ' days')->getTimestamp();

		/** @var array<string, int> $sources */
		$sources = [];
		$capped = false;
		foreach ($this->rows($uid, intdiv($first, self::DAY) * self::DAY) as $row) {
			$hours = $row['hours'];
			// Failures counted without their hour, under concurrency, belong to the last one.
			$lastHour = max(0, min(23, intdiv($row['updatedAt'] - $row['day'], 3600)));
			$hours[$lastHour] += max(0, $row['count'] - array_sum($hours));
			foreach ($hours as $hour => $count) {
				$at = $row['day'] + $hour * 3600;
				if ($count === 0 || $at < $first) {
					continue;
				}
				$key = (new \DateTimeImmutable('@' . $at))->setTimezone($timeZone)->format('Y-m-d');
				if (isset($days[$key])) {
					$days[$key]['count'] += $count;
					$last = $hour === $lastHour ? min($row['updatedAt'], $at + 3599) : $at + 3599;
					$days[$key]['lastAt'] = max($days[$key]['lastAt'], min($last, $now));
				}
			}
			$capped = $capped || count($row['sources']) >= self::MAX_SOURCES;
			foreach ($row['sources'] as $key => $lastSeen) {
				if ($lastSeen >= $first) {
					$sources[$key] = max($sources[$key] ?? 0, $lastSeen);
				}
			}
		}
		return [array_values($days), $sources, $capped];
	}

	/**
	 * The stored days since a UTC day, oldest first, and the counts that
	 * still wait in the memory cache, each as a day of its own.
	 *
	 * @return list<DayRow>
	 */
	private function rows(string $uid, int $sinceDay): array {
		$rows = [];
		foreach ($this->mapper->forUser($uid, $sinceDay, self::RETENTION_DAYS + 1) as $row) {
			$rows[] = [
				'day' => $row['day'],
				'count' => $row['failed_logins'],
				'hours' => self::hours($row['hours']),
				'sources' => self::sources($row['sources']),
				'updatedAt' => $row['updated_at'],
			];
		}
		foreach ($this->buffer->pending(self::BUFFER, $uid) as $pending) {
			$day = intdiv($pending['start'], self::DAY) * self::DAY;
			$hour = intdiv($pending['start'] - $day, 3600);
			$hours = [];
			for ($i = 0; $i < 24; $i++) {
				$hours[] = $i === $hour ? $pending['count'] : 0;
			}
			$rows[] = ['day' => $day, 'count' => $pending['count'], 'hours' => $hours, 'sources' => $pending['details'], 'updatedAt' => $pending['last']];
		}
		return $rows;
	}

	/**
	 * @return list<int> 24 counts
	 */
	private static function hours(?string $json): array {
		$decoded = $json === null ? null : json_decode($json, true);
		$values = is_array($decoded) ? array_values($decoded) : [];
		$hours = [];
		for ($hour = 0; $hour < 24; $hour++) {
			$count = $values[$hour] ?? 0;
			$hours[] = is_int($count) ? max(0, $count) : 0;
		}
		return $hours;
	}

	/**
	 * @return array<string, int> address key => last failure
	 */
	private static function sources(?string $json): array {
		$decoded = $json === null ? null : json_decode($json, true);
		$sources = [];
		if (is_array($decoded)) {
			foreach ($decoded as $key => $lastSeen) {
				if (is_string($key) && is_int($lastSeen) && SourceKey::tryFromIpKey($key) !== null) {
					$sources[$key] = $lastSeen;
				}
			}
		}
		return $sources;
	}

	/**
	 * The sources with these ones' last failures, the latest last; a new
	 * source replaces the longest quiet one when the list is full.
	 *
	 * @param array<string, int> $sources
	 * @param array<string, int> $added
	 * @return array<string, int>
	 */
	private static function withSources(array $sources, array $added): array {
		asort($added);
		foreach ($added as $key => $lastSeen) {
			if (!isset($sources[$key]) && count($sources) >= self::MAX_SOURCES) {
				asort($sources);
				unset($sources[array_key_first($sources)]);
			}
			$sources[$key] = max($sources[$key] ?? 0, $lastSeen);
		}
		return $sources;
	}

	private static function encode(array $data): string {
		return json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
	}
}
