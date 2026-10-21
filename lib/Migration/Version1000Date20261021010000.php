<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\DB\Types;
use OCP\Migration\Attributes\CreateTable;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

/**
 * Accounts under extra protection, and the counters that keep admin
 * notifications and emails aggregated.
 */
#[CreateTable(table: 'ids_protected_accounts', description: 'Accounts whose password logins need extra confirmation for a while')]
#[CreateTable(table: 'ids_alerts', description: 'Hourly counters per check and source that aggregate admin notifications and emails')]
class Version1000Date20261021010000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('ids_protected_accounts')) {
			$table = $schema->createTable('ids_protected_accounts');
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('reason', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->addColumn('detection_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('expires_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['uid']);
			$table->addIndex(['expires_at'], 'ids_prot_expires');
		}

		if (!$schema->hasTable('ids_alerts')) {
			$table = $schema->createTable('ids_alerts');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('check_id', Types::STRING, ['notnull' => true, 'length' => 32]);
			// An ip key, "u:" plus a uid, "instance", or "@mail" for the email limit.
			$table->addColumn('source_key', Types::STRING, ['notnull' => true, 'length' => 80]);
			// The hour (Unix time / 3600) the counter belongs to.
			$table->addColumn('bucket', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('hits', Types::INTEGER, ['notnull' => true, 'unsigned' => true, 'default' => 1]);
			$table->addColumn('detection_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('first_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('last_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['check_id', 'source_key', 'bucket'], 'ids_alert_uniq');
			$table->addIndex(['last_at'], 'ids_alert_last');
		}

		return $schema;
	}
}
