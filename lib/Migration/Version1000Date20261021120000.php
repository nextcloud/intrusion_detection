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
 * Sessions that must confirm sensitive actions because a detection said so
 * in another request, and the history of lockdowns.
 */
#[CreateTable(table: 'ids_risky_sessions', description: 'Session tokens that must confirm sensitive actions after a detection, until the session could have ended')]
#[CreateTable(table: 'ids_lockdowns', description: 'Every lockdown: when, by whom, why, which effects, and how it ended')]
class Version1000Date20261021120000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('ids_risky_sessions')) {
			$table = $schema->createTable('ids_risky_sessions');
			// The database id of the session's token, never the token itself.
			$table->addColumn('token_id', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('check_id', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->addColumn('detection_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('expires_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['token_id']);
			$table->addIndex(['uid'], 'ids_rs_uid');
			$table->addIndex(['expires_at'], 'ids_rs_expires');
		}

		if (!$schema->hasTable('ids_lockdowns')) {
			$table = $schema->createTable('ids_lockdowns');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('started_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			// When it was planned to end; moved by every extension.
			$table->addColumn('planned_end', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('ended_at', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			// An account, "occ" or "automatic".
			$table->addColumn('started_by', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('ended_by', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('reason', Types::STRING, ['notnull' => false, 'length' => 200]);
			// The effects that were on at the start, comma-separated.
			$table->addColumn('effects', Types::STRING, ['notnull' => false, 'length' => 255]);
			// The detection that started it automatically.
			$table->addColumn('detection_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->setPrimaryKey(['id']);
			$table->addIndex(['started_at'], 'ids_ld_started');
			$table->addIndex(['planned_end'], 'ids_ld_planned');
		}

		return $schema;
	}
}
