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
use OCP\Migration\Attributes\ColumnType;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

/**
 * The tries of a pending login's email code, counted on the server, so
 * that parallel requests cannot share one count in the PHP session.
 */
#[AddColumn(table: 'ids_step_up_sessions', name: 'attempts', type: ColumnType::INTEGER, description: 'Email code tries of the pending login')]
class Version1000Date20261021220000 extends SimpleMigrationStep {
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
		if ($table->hasColumn('attempts')) {
			return null;
		}
		$table->addColumn('attempts', Types::INTEGER, ['notnull' => true, 'default' => 0, 'unsigned' => true]);
		return $schema;
	}
}
