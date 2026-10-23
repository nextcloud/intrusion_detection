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
 * A refused login keeps a deadline too, after which the background job
 * ends its session; this tells it from a login that waits.
 */
#[AddColumn(table: 'ids_step_up_sessions', name: 'refused', type: ColumnType::SMALLINT, description: '1 when the login was refused, 0 when it waits for its confirmation')]
class Version1000Date20261023100000 extends SimpleMigrationStep {
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
		if ($table->hasColumn('refused')) {
			return null;
		}
		$table->addColumn('refused', Types::SMALLINT, ['notnull' => true, 'default' => 0, 'unsigned' => true]);
		return $schema;
	}
}
