<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Personal;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
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
 * Counting costs one read and one write by the unique index. Concurrent
 * failures are detected with the count read; after RETRIES attempts the
 * count alone is raised, and the page attributes the remainder to the
 * hour of the last failure.
 *
 * @psalm-import-type IntrusionDetectionFailedLogins from ResponseDefinitions
 */
class FailedLoginStats {
	public const DAYS = 30;
	/** Rows are kept a little longer than shown, for the time zone shift */
	public const RETENTION_DAYS = self::DAYS + 1;
	public const MAX_SOURCES = 20;
	/** The most recent addresses shown */
	public const RECENT = 5;
	public const RETRIES = 3;
	private const DAY = 86400;

	public function __construct(
		private readonly UserDailyMapper $mapper,
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * Whether failures are counted: only while users have the page.
	 */
	public function isEnabled(): bool {
		return $this->settings->getBool(GlobalSettings::PERSONAL_PAGE_ENABLED);
	}

	/**
	 * Count one failed login to an existing account.
	 */
	public function record(string $uid, SourceKey $source): void {
		$now = $this->timeFactory->getTime();
		$day = intdiv($now, self::DAY) * self::DAY;
		$hour = intdiv($now - $day, 3600);
		for ($i = 0; $i < self::RETRIES; $i++) {
			$row = $this->mapper->find($uid, $day);
			if ($row === null) {
				$hours = array_fill(0, 24, 0);
				$hours[$hour] = 1;
				if ($this->mapper->insert($uid, $day, self::encode($hours), self::encode([$source->ipKey => $now]), $now)) {
					return;
				}
				continue;
			}
			$hours = self::hours($row['hours']);
			$hours[$hour]++;
			$sources = self::withSource(self::sources($row['sources']), $source->ipKey, $now);
			if ($this->mapper->replace($uid, $day, $row['failed_logins'], self::encode($hours), self::encode($sources), $now)) {
				return;
			}
		}
		$this->mapper->increment($uid, $day, $now);
	}

	/**
	 * The last DAYS days in the time zone, today last.
	 *
	 * @return IntrusionDetectionFailedLogins
	 */
	public function forUser(string $uid, \DateTimeZone $timeZone): array {
		$now = $this->timeFactory->getTime();
		$midnight = (new \DateTimeImmutable('@' . $now))->setTimezone($timeZone)->setTime(0, 0);
		/** @var array<string, array{day: string, start: int, count: int}> $days */
		$days = [];
		for ($i = self::DAYS - 1; $i >= 0; $i--) {
			$start = $midnight->modify('-' . $i . ' days');
			$days[$start->format('Y-m-d')] = ['day' => $start->format('Y-m-d'), 'start' => $start->getTimestamp(), 'count' => 0];
		}
		$first = $midnight->modify('-' . (self::DAYS - 1) . ' days')->getTimestamp();

		/** @var array<string, int> $sources */
		$sources = [];
		$capped = false;
		foreach ($this->mapper->forUser($uid, intdiv($first, self::DAY) * self::DAY, self::RETENTION_DAYS + 1) as $row) {
			$hours = self::hours($row['hours']);
			// Failures counted without their hour, under concurrency, belong to the last one.
			$lastHour = max(0, min(23, intdiv($row['updated_at'] - $row['day'], 3600)));
			$hours[$lastHour] += max(0, $row['failed_logins'] - array_sum($hours));
			foreach ($hours as $hour => $count) {
				$at = $row['day'] + $hour * 3600;
				if ($count === 0 || $at < $first) {
					continue;
				}
				$key = (new \DateTimeImmutable('@' . $at))->setTimezone($timeZone)->format('Y-m-d');
				if (isset($days[$key])) {
					$days[$key]['count'] += $count;
				}
			}
			$rowSources = self::sources($row['sources']);
			$capped = $capped || count($rowSources) >= self::MAX_SOURCES;
			foreach ($rowSources as $key => $lastSeen) {
				if ($lastSeen >= $first) {
					$sources[$key] = max($sources[$key] ?? 0, $lastSeen);
				}
			}
		}

		arsort($sources);
		$recent = [];
		foreach (array_slice($sources, 0, self::RECENT, true) as $address => $lastSeen) {
			$recent[] = ['address' => (string)$address, 'lastSeenAt' => $lastSeen];
		}
		$list = array_values($days);
		$total = 0;
		foreach ($list as $day) {
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

	public function deleteExpired(): int {
		$today = intdiv($this->timeFactory->getTime(), self::DAY) * self::DAY;
		return $this->mapper->deleteBefore($today - self::RETENTION_DAYS * self::DAY);
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
	 * The sources with this one's last failure; a new source replaces the
	 * longest quiet one when the list is full.
	 *
	 * @param array<string, int> $sources
	 * @return array<string, int>
	 */
	private static function withSource(array $sources, string $key, int $now): array {
		if (!isset($sources[$key]) && count($sources) >= self::MAX_SOURCES) {
			asort($sources);
			unset($sources[array_key_first($sources)]);
		}
		$sources[$key] = $now;
		return $sources;
	}

	private static function encode(array $data): string {
		return json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
	}
}
