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
 * Failed logins per account and day, for the user's own security page.
 */
#[CreateTable(table: 'ids_user_daily', description: 'Failed logins per account and day (UTC), split by hour, with up to 20 addresses they came from, kept 30 days')]
class Version1000Date20261021130000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('ids_user_daily')) {
			$table = $schema->createTable('ids_user_daily');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			// The start of the day in UTC, as a timestamp.
			$table->addColumn('day', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('failed_logins', Types::INTEGER, ['notnull' => true, 'unsigned' => true, 'default' => 0]);
			// JSON list of 24 counts, one per hour of the day (UTC), so that pages can show the user's own days.
			$table->addColumn('hours', Types::STRING, ['notnull' => false, 'length' => 400]);
			// JSON object of up to 20 address keys and when each one last failed.
			$table->addColumn('sources', Types::TEXT, ['notnull' => false]);
			$table->addColumn('updated_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['uid', 'day'], 'ids_ud_uid_day');
			$table->addIndex(['day'], 'ids_ud_day');
		}

		return $schema;
	}
}
