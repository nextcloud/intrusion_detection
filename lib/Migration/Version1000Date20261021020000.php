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
 * Decoy credentials. Only a keyed fingerprint of each secret is stored, as
 * 64 lower-case hex characters, never the secret itself.
 */
#[CreateTable(table: 'ids_decoys', description: 'Decoy credentials planted by administrators, stored as keyed fingerprints')]
class Version1000Date20261021020000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('ids_decoys')) {
			$table = $schema->createTable('ids_decoys');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('login_name', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('secret_hmac', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('format', Types::STRING, ['notnull' => true, 'length' => 16]);
			$table->addColumn('label', Types::STRING, ['notnull' => true, 'length' => 200]);
			$table->addColumn('created_by', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('last_triggered_at', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('trigger_count', Types::INTEGER, ['notnull' => true, 'unsigned' => true, 'default' => 0]);
			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['secret_hmac'], 'ids_decoy_secret');
			$table->addIndex(['login_name'], 'ids_decoy_login');
		}

		return $schema;
	}
}
