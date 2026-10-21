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
 * Which attempts a browser may have made for another site or an email, so
 * that they never make an address a target of a block.
 */
#[AddColumn(table: 'ids_attempts', name: 'lure', type: ColumnType::BOOLEAN, description: 'True when the attempt may have been a lure (a request a browser made for another site); null otherwise')]
class Version1000Date20261021200000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();
		if (!$schema->hasTable('ids_attempts')) {
			return null;
		}
		$table = $schema->getTable('ids_attempts');
		if ($table->hasColumn('lure')) {
			return null;
		}
		$table->addColumn('lure', Types::BOOLEAN, ['notnull' => false, 'default' => null]);
		return $schema;
	}
}
