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
 * Approvals by a second administrator, and the last seen state of the
 * watched security settings.
 *
 * The snapshot keeps a keyed hash of each value, so a change is found without
 * storing the value itself, and a display value only for values that are not
 * secret.
 */
#[CreateTable(table: 'ids_approvals', description: 'Requests that need the approval of a second administrator, such as making someone an administrator')]
#[CreateTable(table: 'ids_config_snapshot', description: 'Keyed hashes and display values of the watched security settings, to find changes')]
class Version1000Date20261021100000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('ids_approvals')) {
			$table = $schema->createTable('ids_approvals');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('kind', Types::STRING, ['notnull' => true, 'length' => 16]);
			$table->addColumn('subject_uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			// A uid, or "occ", "cron" or "unknown" when no user made the request.
			$table->addColumn('requested_by', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('group_id', Types::STRING, ['notnull' => false, 'length' => 255]);
			$table->addColumn('ip', Types::STRING, ['notnull' => false, 'length' => 45]);
			$table->addColumn('status', Types::STRING, ['notnull' => true, 'length' => 16]);
			$table->addColumn('decided_by', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('decided_at', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('expires_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['id']);
			$table->addIndex(['status', 'expires_at'], 'ids_appr_status');
			$table->addIndex(['subject_uid', 'status'], 'ids_appr_subject');
		}

		if (!$schema->hasTable('ids_config_snapshot')) {
			$table = $schema->createTable('ids_config_snapshot');
			// "system:<config.php key>" or "app:<app id>:<key>".
			$table->addColumn('setting_key', Types::STRING, ['notnull' => true, 'length' => 128]);
			$table->addColumn('value_hash', Types::STRING, ['notnull' => true, 'length' => 64]);
			// JSON of the shortened value; null when the value is secret.
			$table->addColumn('display_value', Types::TEXT, ['notnull' => false]);
			$table->addColumn('updated_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['setting_key']);
		}

		return $schema;
	}
}
