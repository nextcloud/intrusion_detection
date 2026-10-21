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
use OCP\Migration\Attributes\AddColumn;
use OCP\Migration\Attributes\AddIndex;
use OCP\Migration\Attributes\ColumnType;
use OCP\Migration\Attributes\IndexType;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

/**
 * What a background job needs to end a login that was left waiting for its
 * confirmation: until when it may wait, where it came from and why.
 */
#[AddColumn(table: 'ids_step_up_sessions', name: 'deadline', type: ColumnType::BIGINT, description: 'Until when a pending login may wait for its confirmation; null once ended or for a refused login')]
#[AddColumn(table: 'ids_step_up_sessions', name: 'ip', type: ColumnType::STRING, description: 'The address of the pending login')]
#[AddColumn(table: 'ids_step_up_sessions', name: 'policies', type: ColumnType::STRING, description: 'Why the pending login needs confirmation, comma separated')]
#[AddIndex(table: 'ids_step_up_sessions', type: IndexType::INDEX, description: 'Pending logins by deadline')]
class Version1000Date20261021170000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();
		if (!$schema->hasTable('ids_step_up_sessions')) {
			return null;
		}
		$table = $schema->getTable('ids_step_up_sessions');
		$changed = false;
		if (!$table->hasColumn('deadline')) {
			$table->addColumn('deadline', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$changed = true;
		}
		if (!$table->hasColumn('ip')) {
			$table->addColumn('ip', Types::STRING, ['notnull' => false, 'length' => 45]);
			$changed = true;
		}
		if (!$table->hasColumn('policies')) {
			$table->addColumn('policies', Types::STRING, ['notnull' => false, 'length' => 255]);
			$changed = true;
		}
		if (!$table->hasIndex('ids_sus_deadline')) {
			$table->addIndex(['deadline'], 'ids_sus_deadline');
			$changed = true;
		}
		return $changed ? $schema : null;
	}
}
