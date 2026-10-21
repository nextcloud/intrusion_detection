<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\Attributes\AddIndex;
use OCP\Migration\Attributes\DropIndex;
use OCP\Migration\Attributes\IndexType;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

/**
 * - The cleanup reads in index order: the hour and day buckets of the
 *   logins and the daily counters get the id after them, so that a batch
 *   starts where the last one ended within a bucket of many rows.
 * - The list of blocks is sorted by when they were created, and the status
 *   counts the blocks of the last day.
 */
#[DropIndex(table: 'ids_logins', type: IndexType::INDEX, description: 'Replaced by the index on hour and id')]
#[AddIndex(table: 'ids_logins', type: IndexType::INDEX, description: 'Logins by hour and id, for the batched cleanup')]
#[DropIndex(table: 'ids_user_daily', type: IndexType::INDEX, description: 'Replaced by the index on day and id')]
#[AddIndex(table: 'ids_user_daily', type: IndexType::INDEX, description: 'Daily counters by day and id, for the batched cleanup')]
#[AddIndex(table: 'ids_bans', type: IndexType::INDEX, description: 'Blocks by creation time, for the list and the daily counts')]
class Version1000Date20261021210000 extends SimpleMigrationStep {
	/** table => [old index, new index, columns] */
	private const REPLACED = [
		'ids_logins' => ['ids_login_hour', 'ids_login_hour_id', ['hour', 'id']],
		'ids_user_daily' => ['ids_ud_day', 'ids_ud_day_id', ['day', 'id']],
	];

	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();
		$changed = false;
		foreach (self::REPLACED as $name => [$old, $new, $columns]) {
			if (!$schema->hasTable($name)) {
				continue;
			}
			$table = $schema->getTable($name);
			if (!$table->hasIndex($new)) {
				$table->addIndex($columns, $new);
				$changed = true;
			}
			if ($table->hasIndex($old)) {
				$table->dropIndex($old);
				$changed = true;
			}
		}
		if ($schema->hasTable('ids_bans')) {
			$table = $schema->getTable('ids_bans');
			if (!$table->hasIndex('ids_ban_created')) {
				$table->addIndex(['created_at'], 'ids_ban_created');
				$changed = true;
			}
		}
		return $changed ? $schema : null;
	}
}
