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
 * The security changes of accounts, and the one-time links that let the
 * previous email address lock an account.
 *
 * A security change keeps the old email address only masked. The full old
 * address is kept encrypted for a day at most, so that the lock link can be
 * sent to it when the takeover check fires a little later. A lock link is
 * stored as a keyed fingerprint of its token, never the token.
 */
#[CreateTable(table: 'ids_security_changes', description: 'Security changes of accounts: email, password, second factor, app passwords and connected devices')]
#[CreateTable(table: 'ids_lock_links', description: 'One-time links that let the previous email address lock an account')]
class Version1000Date20261021090000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('ids_security_changes')) {
			$table = $schema->createTable('ids_security_changes');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('type', Types::STRING, ['notnull' => true, 'length' => 32]);
			// self, admin, occ, reset or system: only "self" counts towards the takeover check.
			$table->addColumn('via', Types::STRING, ['notnull' => true, 'length' => 16]);
			$table->addColumn('actor_uid', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('old_value_hint', Types::STRING, ['notnull' => false, 'length' => 255]);
			$table->addColumn('new_value_hint', Types::STRING, ['notnull' => false, 'length' => 255]);
			// The encrypted previous email address, removed after a day.
			$table->addColumn('notify_to', Types::TEXT, ['notnull' => false]);
			// The app password or device token the change is about.
			$table->addColumn('ref_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('detail', Types::STRING, ['notnull' => false, 'length' => 100]);
			$table->addColumn('session_token_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('ip', Types::STRING, ['notnull' => false, 'length' => 45]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['id']);
			$table->addIndex(['uid', 'created_at'], 'ids_sc_uid');
			$table->addIndex(['created_at'], 'ids_sc_created');
			$table->addIndex(['ip', 'created_at'], 'ids_sc_ip');
		}

		if (!$schema->hasTable('ids_lock_links')) {
			$table = $schema->createTable('ids_lock_links');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			// Hex keyed fingerprint of the token.
			$table->addColumn('token_hash', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('sent_to_hint', Types::STRING, ['notnull' => true, 'length' => 255]);
			$table->addColumn('detection_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('change_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('expires_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('used_at', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('used_ip', Types::STRING, ['notnull' => false, 'length' => 45]);
			$table->setPrimaryKey(['id']);
			$table->addIndex(['uid'], 'ids_ll_uid');
			$table->addIndex(['detection_id'], 'ids_ll_detection');
			$table->addIndex(['expires_at'], 'ids_ll_expires');
		}

		return $schema;
	}
}
