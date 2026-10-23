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
 * The settings change a request for approval holds back, as JSON, for the
 * requests that switch the four-eyes approval off.
 */
#[AddColumn(table: 'ids_approvals', name: 'payload', type: ColumnType::TEXT, description: 'The settings change that waits for approval, as JSON')]
class Version1000Date20261023110000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();
		$table = $schema->getTable('ids_approvals');
		if ($table->hasColumn('payload')) {
			return null;
		}
		$table->addColumn('payload', Types::TEXT, ['notnull' => false]);
		return $schema;
	}
}
