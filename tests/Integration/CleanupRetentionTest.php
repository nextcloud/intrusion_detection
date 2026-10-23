<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\BackgroundJob\Cleanup;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\State\HotState;
use OCP\Server;
use OCP\Snowflake\ISnowflakeGenerator;
use PHPUnit\Framework\Attributes\Group;

/**
 * What one run of the cleanup job deletes from each table, and what it
 * keeps: a row a little past its retention goes, a row a little within it
 * stays.
 */
#[Group('DB')]
class CleanupRetentionTest extends IntegrationTestCase {
	private const MARGIN = 600;
	private const DAY = 86400;
	/** The tables whose rows have a snowflake id */
	private const SNOWFLAKE_TABLES = ['ids_attempts', 'ids_logins', 'ids_detections', 'ids_detection_hourly', 'ids_bans', 'ids_alerts', 'ids_trusted_networks', 'ids_known_devices', 'ids_login_history', 'ids_security_changes', 'ids_lock_links', 'ids_user_daily'];

	public function testEveryTableKeepsItsRowsForTheirRetentionOnly(): void {
		$now = time();
		$retained = $this->appSettings()->retentionDays() * self::DAY;
		$banHistory = max(30 * self::DAY, $this->appSettings()->banHistoryDays() * self::DAY);
		$today = intdiv($now, self::DAY) * self::DAY;
		$rows = [
			'ids_attempts' => fn (int $at, string $mark): array => ['kind' => 1, 'ip_key' => $mark, 'net_key' => 'n', 'created_at' => $at],
			'ids_logins' => fn (int $at, string $mark): array => ['ip_key' => $mark, 'net_key' => 'n', 'uid' => 'alice', 'hour' => intdiv($at, 3600)],
			'ids_detections' => fn (int $at, string $mark): array => ['check_id' => $mark, 'severity' => 'low', 'created_at' => $at, 'last_seen_at' => $at],
			'ids_detection_hourly' => fn (int $at, string $mark): array => ['hour' => intdiv($at, 3600), 'check_id' => $mark, 'severity' => 'low', 'created' => 1],
			'ids_bans' => fn (int $at, string $mark): array => ['reference' => substr($mark, 0, 8), 'cidr' => '192.0.2.1/32', 'scope' => 'ip', 'ban_key' => $mark, 'level' => 1, 'check_id' => 'trap_url', 'created_at' => $at - self::DAY, 'expires_at' => $at],
			'ids_flags' => fn (int $at, string $mark): array => ['flag_key' => $mark, 'reason' => 'attack', 'expires_at' => $at],
			'ids_protected_accounts' => fn (int $at, string $mark): array => ['uid' => $mark, 'reason' => 'attack', 'created_at' => $at - self::DAY, 'expires_at' => $at],
			'ids_alerts' => fn (int $at, string $mark): array => ['check_id' => 'trap_url', 'source_key' => $mark, 'bucket' => 1, 'first_at' => $at, 'last_at' => $at],
			'ids_reset_suppressions' => fn (int $at, string $mark): array => ['uid' => $mark, 'created_at' => $at - 2 * self::DAY, 'expires_at' => $at],
			'ids_token_origin' => fn (int $at, string $mark): array => ['token_id' => $mark === 'old' ? 1 : 2, 'uid' => $mark, 'created_at' => $at],
			'ids_trusted_networks' => fn (int $at, string $mark): array => ['uid' => $mark, 'net_key' => 'n', 'created_at' => $at - self::DAY, 'expires_at' => $at],
			'ids_step_up_sessions' => fn (int $at, string $mark): array => ['session_key' => $mark, 'uid' => $mark, 'created_at' => $at - self::DAY, 'expires_at' => $at],
			'ids_known_devices' => fn (int $at, string $mark): array => ['uid' => $mark, 'device_hmac' => $mark, 'created_at' => $at, 'last_seen_at' => $at],
			'ids_login_history' => fn (int $at, string $mark): array => ['uid' => $mark, 'created_at' => $at, 'method' => 'password', 'confirmed_by' => 'none'],
			'ids_security_changes' => fn (int $at, string $mark): array => ['uid' => $mark, 'type' => 'email', 'via' => 'self', 'created_at' => $at],
			'ids_lock_links' => fn (int $at, string $mark): array => ['uid' => $mark, 'token_hash' => $mark, 'sent_to_hint' => 'a***@example.com', 'expires_at' => $at],
			'ids_user_daily' => fn (int $at, string $mark): array => ['uid' => $mark, 'day' => $at, 'updated_at' => $at],
			'ids_blocklist_stats' => fn (int $at, string $mark): array => ['list_id' => $mark, 'day' => gmdate('Y-m-d', $at), 'matches' => 1, 'sample' => '[]'],
		];
		// The time each table's rows are kept until, and the column that holds the row's time
		$until = [
			'ids_attempts' => $now - 3600,
			'ids_logins' => $now - self::DAY - 3600,
			'ids_detections' => $now - $retained,
			'ids_detection_hourly' => $now - 100 * self::DAY - 3600,
			'ids_bans' => $now - $banHistory,
			'ids_flags' => $now,
			'ids_protected_accounts' => $now,
			'ids_alerts' => $now - 30 * self::DAY,
			'ids_reset_suppressions' => $now,
			'ids_token_origin' => $now - 30 * self::DAY,
			'ids_trusted_networks' => $now,
			'ids_step_up_sessions' => $now,
			'ids_known_devices' => $now - 180 * self::DAY,
			'ids_login_history' => $now - $retained,
			'ids_security_changes' => $now - $retained,
			'ids_lock_links' => $now,
			'ids_user_daily' => $today - 31 * self::DAY,
			'ids_blocklist_stats' => $now - 30 * self::DAY,
		];
		$this->assertSame(array_keys($rows), array_keys($until));
		foreach ($rows as $table => $row) {
			$margin = in_array($table, ['ids_logins', 'ids_detection_hourly'], true) ? 3600 : (in_array($table, ['ids_user_daily', 'ids_blocklist_stats'], true) ? self::DAY : self::MARGIN);
			$this->insert($table, $row($until[$table] - $margin, 'old'));
			$this->insert($table, $row($until[$table] + $margin, 'new'));
		}
		$detections = $this->column('ids_detections', 'id', 'check_id');
		foreach ($detections as $mark => $id) {
			$this->insert('ids_detection_accounts', ['detection_id' => $id, 'uid' => $mark]);
		}

		self::invokePrivate(Server::get(Cleanup::class), 'run', [null]);

		$marks = [
			'ids_attempts' => 'ip_key', 'ids_logins' => 'ip_key', 'ids_detections' => 'check_id', 'ids_detection_hourly' => 'check_id',
			'ids_bans' => 'ban_key', 'ids_flags' => 'flag_key', 'ids_alerts' => 'source_key', 'ids_blocklist_stats' => 'list_id',
		];
		$left = [];
		foreach (array_keys($rows) as $table) {
			$left[$table] = array_keys($this->column($table, $marks[$table] ?? 'uid', $marks[$table] ?? 'uid'));
		}
		$left['ids_detection_accounts'] = array_keys($this->column('ids_detection_accounts', 'uid', 'uid'));
		$expected = array_fill_keys(array_keys($rows), ['new']);
		$expected['ids_detection_accounts'] = ['new'];
		$this->assertSame($expected, $left);
	}

	public function testAddressesOfSecurityChangesAreForgottenAfterADay(): void {
		$now = time();
		$this->insert('ids_security_changes', ['uid' => 'old', 'type' => 'email', 'via' => 'self', 'notify_to' => 'encrypted', 'created_at' => $now - self::DAY - self::MARGIN]);
		$this->insert('ids_security_changes', ['uid' => 'new', 'type' => 'email', 'via' => 'self', 'notify_to' => 'encrypted', 'created_at' => $now - self::DAY + self::MARGIN]);

		self::invokePrivate(Server::get(Cleanup::class), 'run', [null]);

		$this->assertSame(['new' => 'encrypted', 'old' => null], $this->column('ids_security_changes', 'notify_to', 'uid'));
	}

	public function testALoginLeftWaitingPastItsDeadlineIsEnded(): void {
		$now = time();
		$this->settingsEditor()->setGlobal(GlobalSettings::ENABLED, false);
		$this->insert('ids_step_up_sessions', ['session_key' => 'k', 'uid' => 'alice', 'created_at' => $now - 7200, 'expires_at' => $now + 3600, 'deadline' => $now - self::MARGIN]);
		$this->insert('ids_login_history', ['uid' => 'alice', 'created_at' => $now - 7200, 'method' => 'password', 'confirmed_by' => 'none', 'step_up' => LoginHistory::STEP_UP_PENDING]);

		self::invokePrivate(Server::get(Cleanup::class), 'run', [null]);

		$this->assertSame(['alice' => LoginHistory::STEP_UP_FAILED], $this->column('ids_login_history', 'step_up', 'uid'));
		$this->assertSame(['alice' => null], $this->column('ids_step_up_sessions', 'deadline', 'uid'), 'Kept without a deadline, so that the session cannot come back');
	}

	public function testTheFloodStateFollowsTheAttemptsLeftAfterTheirCleanup(): void {
		$hotState = Server::get(HotState::class);
		$hotState->setAttemptsFloodUntil(time() + 600);

		self::invokePrivate(Server::get(Cleanup::class), 'run', [null]);

		$this->assertSame(0, $hotState->attemptsFloodUntil(), 'An empty table is no flood');
	}

	/**
	 * @param array<string, int|string|null> $row
	 */
	private function insert(string $table, array $row): void {
		if (in_array($table, self::SNOWFLAKE_TABLES, true)) {
			$row['id'] = Server::get(ISnowflakeGenerator::class)->nextId();
		}
		$qb = $this->db->getQueryBuilder();
		$qb->insert($table);
		foreach ($row as $column => $value) {
			$qb->setValue($column, $qb->createNamedParameter($value));
		}
		$qb->executeStatement();
	}

	/**
	 * @return array<string, mixed> key column => value column, by key
	 */
	private function column(string $table, string $value, string $key): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select($value, $key)->from($table);
		$result = $qb->executeQuery();
		$rows = [];
		while ($row = $result->fetch()) {
			$rows[(string)$row[$key]] = $row[$value] === null ? null : (is_numeric($row[$value]) ? (int)$row[$value] : $row[$value]);
		}
		$result->closeCursor();
		ksort($rows);
		return $rows;
	}
}
