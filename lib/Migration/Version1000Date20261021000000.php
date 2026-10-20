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
 * The base tables: failed attempts, successful logins, detections, bans and flags.
 *
 * Fingerprints are stored as lower-case hex strings (32 characters for 16 bytes),
 * so equality lookups and indexes behave the same on every database.
 */
#[CreateTable(table: 'ids_attempts', description: 'Failed login, share and reset attempts, kept for one hour')]
#[CreateTable(table: 'ids_logins', description: 'Which accounts logged in from which address per hour, kept for one day')]
#[CreateTable(table: 'ids_detections', description: 'Detections with their explanation and the actions taken')]
#[CreateTable(table: 'ids_bans', description: 'Blocked addresses and networks')]
#[CreateTable(table: 'ids_flags', description: 'Flagged addresses and passwords that need extra confirmation')]
class Version1000Date20261021000000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('ids_attempts')) {
			$table = $schema->createTable('ids_attempts');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('kind', Types::SMALLINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('ip_key', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('net_key', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('name_hmac', Types::STRING, ['notnull' => false, 'length' => 32]);
			$table->addColumn('uid', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('share_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('pw_fp', Types::STRING, ['notnull' => false, 'length' => 32]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['id']);
			$table->addIndex(['ip_key', 'created_at'], 'ids_att_ip');
			$table->addIndex(['net_key', 'created_at'], 'ids_att_net');
			$table->addIndex(['pw_fp', 'created_at'], 'ids_att_pw');
			$table->addIndex(['uid', 'kind', 'created_at'], 'ids_att_uid');
			$table->addIndex(['share_id', 'created_at'], 'ids_att_share');
			$table->addIndex(['kind', 'created_at'], 'ids_att_kind');
		}

		if (!$schema->hasTable('ids_logins')) {
			$table = $schema->createTable('ids_logins');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('ip_key', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('net_key', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('hour', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['ip_key', 'uid', 'hour'], 'ids_login_uniq');
			$table->addIndex(['net_key', 'hour'], 'ids_login_net');
			$table->addIndex(['hour'], 'ids_login_hour');
		}

		if (!$schema->hasTable('ids_detections')) {
			$table = $schema->createTable('ids_detections');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('check_id', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->addColumn('severity', Types::STRING, ['notnull' => true, 'length' => 8]);
			// Oracle cannot store a non-null boolean, so the column is nullable.
			$table->addColumn('enforced', Types::BOOLEAN, ['notnull' => false, 'default' => false]);
			$table->addColumn('ip', Types::STRING, ['notnull' => false, 'length' => 45]);
			$table->addColumn('net_key', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('uid', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('share_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('merge_key', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('explanation', Types::TEXT, ['notnull' => false]);
			$table->addColumn('actions', Types::TEXT, ['notnull' => false]);
			$table->addColumn('user_verdict', Types::STRING, ['notnull' => false, 'length' => 16]);
			$table->addColumn('verdict_at', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('last_seen_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('hits', Types::INTEGER, ['notnull' => true, 'unsigned' => true, 'default' => 1]);
			$table->setPrimaryKey(['id']);
			$table->addIndex(['created_at'], 'ids_det_created');
			$table->addIndex(['check_id', 'created_at'], 'ids_det_check');
			$table->addIndex(['uid', 'created_at'], 'ids_det_uid');
			$table->addIndex(['ip', 'created_at'], 'ids_det_ip');
			$table->addIndex(['merge_key', 'last_seen_at'], 'ids_det_merge');
		}

		if (!$schema->hasTable('ids_bans')) {
			$table = $schema->createTable('ids_bans');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('reference', Types::STRING, ['notnull' => true, 'length' => 8]);
			// "range" is a reserved word in MySQL 8.
			$table->addColumn('cidr', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('scope', Types::STRING, ['notnull' => true, 'length' => 8]);
			$table->addColumn('ban_key', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('level', Types::SMALLINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('check_id', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->addColumn('detection_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('created_by', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('note', Types::STRING, ['notnull' => false, 'length' => 255]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('expires_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('lifted_at', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('lifted_by', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('lift_note', Types::STRING, ['notnull' => false, 'length' => 255]);
			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['reference'], 'ids_ban_ref');
			$table->addIndex(['ban_key', 'expires_at'], 'ids_ban_key');
			$table->addIndex(['expires_at'], 'ids_ban_expires');
		}

		if (!$schema->hasTable('ids_flags')) {
			$table = $schema->createTable('ids_flags');
			$table->addColumn('flag_key', Types::STRING, ['notnull' => true, 'length' => 80]);
			$table->addColumn('reason', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->addColumn('detection_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('expires_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['flag_key']);
			$table->addIndex(['expires_at'], 'ids_flag_expires');
		}

		return $schema;
	}
}
