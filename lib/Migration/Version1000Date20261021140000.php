<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Migration;

use Closure;
use OCA\IntrusionDetection\Detection\DetectionAccounts;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCP\DB\ISchemaWrapper;
use OCP\DB\Types;
use OCP\Migration\Attributes\AddIndex;
use OCP\Migration\Attributes\CreateTable;
use OCP\Migration\Attributes\IndexType;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

/**
 * Indexes and side tables that keep the statistics, the user deletion and
 * the incident reports off full scans.
 */
#[CreateTable(table: 'ids_detection_accounts', description: 'Which accounts each detection is about or mentions, for deleting accounts and for incident reports')]
#[CreateTable(table: 'ids_detection_hourly', description: 'Detections per hour, check, severity and enforcement, for the statistics and the metrics')]
#[AddIndex(table: 'ids_logins', type: IndexType::INDEX, description: 'Deleting the logins of a deleted account')]
#[AddIndex(table: 'ids_alerts', type: IndexType::INDEX, description: 'Deleting the notification counters of a deleted account')]
class Version1000Date20261021140000 extends SimpleMigrationStep {
	public function __construct(
		private readonly DetectionAccounts $accounts,
		private readonly DetectionTotals $totals,
	) {
	}

	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('ids_detection_accounts')) {
			$table = $schema->createTable('ids_detection_accounts');
			$table->addColumn('detection_id', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->setPrimaryKey(['detection_id', 'uid']);
			$table->addIndex(['uid', 'detection_id'], 'ids_detacc_uid');
		}

		if (!$schema->hasTable('ids_detection_hourly')) {
			$table = $schema->createTable('ids_detection_hourly');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			// Unix time / 3600 of the hour.
			$table->addColumn('hour', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('check_id', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->addColumn('severity', Types::STRING, ['notnull' => true, 'length' => 16]);
			// 1 when Nextcloud acted on the detections, 0 when they were only observed.
			$table->addColumn('enforced', Types::SMALLINT, ['notnull' => true, 'unsigned' => true, 'default' => 0]);
			// New detections in the hour.
			$table->addColumn('created', Types::INTEGER, ['notnull' => true, 'unsigned' => true, 'default' => 0]);
			// Detections whose severity rose to this one in the hour.
			$table->addColumn('raised', Types::INTEGER, ['notnull' => true, 'unsigned' => true, 'default' => 0]);
			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['hour', 'check_id', 'severity', 'enforced'], 'ids_dh_uniq');
		}

		$logins = $schema->getTable('ids_logins');
		if (!$logins->hasIndex('ids_login_uid')) {
			$logins->addIndex(['uid'], 'ids_login_uid');
		}

		// The unique index starts with check_id, so it does not serve a lookup by source_key alone.
		$alerts = $schema->getTable('ids_alerts');
		if (!$alerts->hasIndex('ids_alert_src')) {
			$alerts->addIndex(['source_key'], 'ids_alert_src');
		}

		return $schema;
	}

	/**
	 * Fill both side tables from the detections stored before they existed.
	 * A repeated run adds nothing.
	 */
	#[\Override]
	public function postSchemaChange(IOutput $output, Closure $schemaClosure, array $options): void {
		$this->accounts->backfill();
		$this->totals->backfill();
	}
}
