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
 * How many attempts each stored attempt stands for: more than one for the
 * attempts kept while a flood was sampled.
 */
#[AddColumn(table: 'ids_attempts', name: 'weight', type: ColumnType::SMALLINT, description: 'How many attempts the row stands for while a flood is sampled')]
class Version1000Date20261021150000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();
		$table = $schema->getTable('ids_attempts');
		if ($table->hasColumn('weight')) {
			return null;
		}
		$table->addColumn('weight', Types::SMALLINT, ['notnull' => true, 'unsigned' => true, 'default' => 1]);
		return $schema;
	}
}
