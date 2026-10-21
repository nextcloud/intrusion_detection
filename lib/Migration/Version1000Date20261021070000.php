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
 * The downloaded blocklists and network attribute lists, and their daily match counters.
 *
 * Addresses are 32 lower-case hex characters (16 bytes, IPv4 as IPv4-mapped),
 * so string order is address order on every database.
 */
#[CreateTable(table: 'ids_blocklist_ranges', description: 'Address ranges of the downloaded blocklists and network attribute lists')]
#[CreateTable(table: 'ids_blocklist_stats', description: 'Per list and day: how often an address on the list was looked up, and the last matched addresses')]
class Version1000Date20261021070000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('ids_blocklist_ranges')) {
			$table = $schema->createTable('ids_blocklist_ranges');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('list_id', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->addColumn('version', Types::INTEGER, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('family', Types::SMALLINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('range_start', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->addColumn('range_end', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->setPrimaryKey(['id']);
			// The lookup is "the last range of this list version that starts at or
			// below the address": equality on the first three columns, then a
			// backwards range scan that stops at the first row. The same index
			// serves deleting a whole version.
			$table->addIndex(['list_id', 'version', 'family', 'range_start'], 'ids_blr_lookup');
		}

		if (!$schema->hasTable('ids_blocklist_stats')) {
			$table = $schema->createTable('ids_blocklist_stats');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('list_id', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->addColumn('day', Types::STRING, ['notnull' => true, 'length' => 10]);
			$table->addColumn('matches', Types::BIGINT, ['notnull' => true, 'unsigned' => true, 'default' => 0]);
			$table->addColumn('sample', Types::TEXT, ['notnull' => false]);
			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['list_id', 'day'], 'ids_bls_day');
		}

		return $schema;
	}
}
