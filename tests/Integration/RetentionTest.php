<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\BatchedDelete;
use OCA\IntrusionDetection\Db\FlagMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Db\SecurityChangeMapper;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Retention deletes run in batches through an index, and the flood check
 * reads a bounded number of rows instead of counting the table.
 */
#[Group('DB')]
class RetentionTest extends IntegrationTestCase {
	public function testExpiredAttemptsOfEveryKindAreDeletedAndNewOnesKept(): void {
		$mapper = Server::get(AttemptMapper::class);
		foreach (AttemptKind::cases() as $kind) {
			$mapper->insert($kind, 'k1', 'n1', null, null, null, null, 1000);
			$mapper->insert($kind, 'k2', 'n2', null, null, null, null, 5000);
		}
		$this->assertSame(count(AttemptKind::cases()), $mapper->deleteOlderThan(2000));
		$this->assertSame(count(AttemptKind::cases()), $this->rows(AttemptMapper::TABLE));
		$this->assertSame(0, $mapper->deleteOlderThan(2000), 'nothing left to delete');
	}

	public function testBatchesStopAtTheirLimit(): void {
		$mapper = Server::get(FlagMapper::class);
		for ($i = 0; $i < 7; $i++) {
			$mapper->flag('ip:test' . $i, 'attack', 100 + $i, null);
		}
		$where = static fn (IQueryBuilder $qb): IQueryBuilder => $qb->where($qb->expr()->lte('expires_at', $qb->createNamedParameter(1000, IQueryBuilder::PARAM_INT)));

		$queries = $this->queries();
		$deleted = BatchedDelete::run($this->db, FlagMapper::TABLE, 'flag_key', 'expires_at', $where, IQueryBuilder::PARAM_STR_ARRAY, batch: 2, maxBatches: 2);
		$this->assertSame(4, $deleted, 'two batches of two');
		$this->assertSame(4, $this->queries() - $queries, 'one select and one delete per batch');
		$this->assertSame(3, $this->rows(FlagMapper::TABLE));

		$this->assertSame(3, BatchedDelete::run($this->db, FlagMapper::TABLE, 'flag_key', 'expires_at', $where, IQueryBuilder::PARAM_STR_ARRAY, batch: 2));
		$this->assertSame(0, $this->rows(FlagMapper::TABLE));
	}

	public function testBatchesStartWhereTheLastOneEndedAlsoWithinOneValue(): void {
		$logins = Server::get(LoginMapper::class);
		// Five logins in each of two hours: batches of two split the hours.
		for ($i = 0; $i < 10; $i++) {
			$logins->record('4:198.51.100.' . $i, '4n:198.51.100', 'user' . $i, 400000 + intdiv($i, 5));
		}
		$where = static fn (IQueryBuilder $qb): IQueryBuilder => $qb->where($qb->expr()->lt('hour', $qb->createNamedParameter(500000, IQueryBuilder::PARAM_INT)));

		$seen = [];
		foreach (BatchedDelete::batches($this->db, LoginMapper::TABLE, 'id', 'hour', $where, batch: 2) as $ids) {
			$this->assertLessThanOrEqual(2, count($ids));
			array_push($seen, ...$ids);
		}
		$this->assertCount(10, $seen, 'every row once, though none was deleted');
		$this->assertSame($seen, array_values(array_unique($seen)));

		$this->assertSame(10, $logins->deleteOlderThan(500000));
		$this->assertSame(0, $this->rows(LoginMapper::TABLE));
	}

	public function testAttemptsAreDeletedOneKindAfterTheOtherInTimeOrder(): void {
		$mapper = Server::get(AttemptMapper::class);
		foreach ([AttemptKind::PasswordLogin, AttemptKind::PasswordReset] as $kind) {
			$mapper->insert($kind, 'k1', 'n1', null, null, null, null, 1000);
		}
		$queries = $this->queries();
		$this->assertSame(2, $mapper->deleteOlderThan(2000));
		// A select per kind, a delete for each kind that had rows.
		$this->assertSame(count(AttemptKind::cases()) + 2, $this->queries() - $queries);
	}

	public function testAFlagIsOnlyExtendedOnceLessThanHalfRemains(): void {
		$mapper = Server::get(FlagMapper::class);
		$this->assertTrue($mapper->flag('ip:attack', 'attack', 1000 + 3600, null, 1000));
		$queries = $this->db->getInner()->getStats()['executed'];
		$this->assertFalse($mapper->flag('ip:attack', 'attack', 1010 + 3600, null, 1010), 'most of the hour is left');
		$this->assertFalse($mapper->flag('ip:attack', 'attack', 2700 + 3600, null, 2700));
		$this->assertTrue($mapper->flag('ip:attack', 'attack', 2900 + 3600, null, 2900), 'less than half is left');
		$this->assertSame(['ip:attack' => 'attack'], $mapper->active(['ip:attack'], 2900 + 3599));
		$this->assertSame([], $mapper->active(['ip:attack'], 2900 + 3600));
		$this->assertTrue($mapper->flag('ip:other', 'attack', 5000, null), 'without a time a later end always extends');
	}

	public function testFlagRetentionDeletesOnlyExpiredFlags(): void {
		$mapper = Server::get(FlagMapper::class);
		$mapper->flag('ip:old', 'attack', 100, null);
		$mapper->flag('ip:new', 'attack', 5000, null);
		$this->assertSame(1, $mapper->deleteExpired(1000));
		$this->assertSame(['ip:new' => 'attack'], $mapper->active(['ip:old', 'ip:new'], 1000));
	}

	public function testTheFloodCheckReadsPastTheLimitOnly(): void {
		$mapper = Server::get(AttemptMapper::class);
		for ($i = 0; $i < 3; $i++) {
			$mapper->insert(AttemptKind::PasswordLogin, 'k' . $i, 'n', null, null, null, null, 1000);
		}
		$this->assertTrue($mapper->hasMoreThan(2));
		$this->assertFalse($mapper->hasMoreThan(3));
	}

	public function testAddressesAreForgottenWithinTheLookBack(): void {
		$mapper = Server::get(SecurityChangeMapper::class);
		$base = ['uid' => 'alice', 'type' => 'email', 'via' => 'self', 'notify_to' => 'encrypted'];
		$old = $mapper->insert($base + ['created_at' => 100]);
		$recent = $mapper->insert($base + ['created_at' => 5000]);
		$this->assertSame(1, $mapper->forgetAddressesBefore(6000, 1000));
		$this->assertSame(1, $mapper->forgetAddressesBefore(6000), 'without a lower bound the rest goes as well');
		$this->assertSame([$old => null, $recent => null], $this->notifyTo());
		$queries = $this->queries();
		$this->assertSame(0, $mapper->forgetAddressesBefore(6000));
		$this->assertSame(1, $this->queries() - $queries, 'one select of ids finds nothing to update');
	}

	public function testIndexesForDeletingAnAccountExist(): void {
		$schema = $this->db->createSchema();
		$prefix = Server::get(\OCP\IConfig::class)->getSystemValueString('dbtableprefix', 'oc_');
		$this->assertTrue($schema->getTable($prefix . 'ids_logins')->hasIndex('ids_login_uid'));
		$this->assertTrue($schema->getTable($prefix . 'ids_alerts')->hasIndex('ids_alert_src'));
	}

	private function rows(string $table): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*'))->from($table);
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	/**
	 * @return array<int, ?string>
	 */
	private function notifyTo(): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id', 'notify_to')->from(SecurityChangeMapper::TABLE)->orderBy('id');
		$result = $qb->executeQuery();
		$rows = [];
		while ($row = $result->fetch()) {
			$rows[(int)$row['id']] = $row['notify_to'] === null ? null : (string)$row['notify_to'];
		}
		$result->closeCursor();
		return $rows;
	}

	private function queries(): int {
		return $this->db->getInner()->getStats()['executed'];
	}
}
