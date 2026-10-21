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
 * Where each app password came from: the session and the address that
 * created it. Core does not keep this, and ending a suspicious session must
 * also end the app passwords created from it.
 */
#[CreateTable(table: 'ids_token_origin', description: 'The session and address each app password was created from, kept for 30 days')]
class Version1000Date20261021030000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('ids_token_origin')) {
			$table = $schema->createTable('ids_token_origin');
			// The id of the app password in core's authtoken table.
			$table->addColumn('token_id', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('ip', Types::STRING, ['notnull' => false, 'length' => 45]);
			// The token of the session (or app password) that created it, if any.
			$table->addColumn('session_token_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['token_id']);
			$table->addIndex(['session_token_id'], 'ids_torig_session');
			$table->addIndex(['uid', 'created_at'], 'ids_torig_uid');
			$table->addIndex(['created_at'], 'ids_torig_created');
		}

		return $schema;
	}
}
