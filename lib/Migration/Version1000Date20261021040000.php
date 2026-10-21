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
 * The networks users confirmed as their own, and the browser sessions whose
 * login still waits for its extra confirmation (or was refused), so that
 * such a session cannot be resumed through its remember-me cookie or its
 * session token.
 */
#[CreateTable(table: 'ids_trusted_networks', description: 'Networks a user confirmed as their own by answering "Yes, it was me", kept for 30 days')]
#[CreateTable(table: 'ids_step_up_sessions', description: 'Keyed fingerprints of sessions whose login was not confirmed, kept while the session could be resumed')]
class Version1000Date20261021040000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('ids_trusted_networks')) {
			$table = $schema->createTable('ids_trusted_networks');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			// The /24 (IPv4) or /64 (IPv6) network.
			$table->addColumn('net_key', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('expires_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			// The detection the user answered.
			$table->addColumn('detection_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['uid', 'net_key'], 'ids_tn_uid_net');
			$table->addIndex(['expires_at'], 'ids_tn_expires');
		}

		if (!$schema->hasTable('ids_step_up_sessions')) {
			$table = $schema->createTable('ids_step_up_sessions');
			// Hex of a keyed HMAC of the session id; never the session id itself.
			$table->addColumn('session_key', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('expires_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['session_key']);
			$table->addIndex(['uid'], 'ids_sus_uid');
			$table->addIndex(['expires_at'], 'ids_sus_expires');
		}

		return $schema;
	}
}
