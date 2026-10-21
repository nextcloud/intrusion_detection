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
 * Accounts whose password reset emails are held back while someone floods them.
 */
#[CreateTable(table: 'ids_reset_suppressions', description: 'Accounts whose password reset emails are not sent for a while, because someone requested too many')]
class Version1000Date20261021050000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('ids_reset_suppressions')) {
			$table = $schema->createTable('ids_reset_suppressions');
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('detection_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('expires_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['uid']);
			$table->addIndex(['expires_at'], 'ids_rsup_expires');
		}

		return $schema;
	}
}
