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
 * The browsers users chose to remember after confirming a login, and one
 * row per successful login.
 */
#[CreateTable(table: 'ids_known_devices', description: 'Keyed fingerprints of the device cookies of browsers a user chose to remember, kept until 180 days after their last use')]
#[CreateTable(table: 'ids_login_history', description: 'One row per successful login: when, from where, with which client and how it was confirmed, kept 90 days')]
class Version1000Date20261021080000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('ids_known_devices')) {
			$table = $schema->createTable('ids_known_devices');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			// Hex of a keyed HMAC of the random device id in the cookie; never the id itself.
			$table->addColumn('device_hmac', Types::STRING, ['notnull' => true, 'length' => 64]);
			// Browser and platform families from the user agent, e.g. "firefox" and "linux".
			$table->addColumn('family', Types::STRING, ['notnull' => false, 'length' => 32]);
			$table->addColumn('platform', Types::STRING, ['notnull' => false, 'length' => 32]);
			$table->addColumn('label', Types::STRING, ['notnull' => false, 'length' => 100]);
			// The /24 (IPv4) or /64 (IPv6) network the device was first confirmed from.
			$table->addColumn('net_key', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('last_seen_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['uid', 'device_hmac'], 'ids_kd_uid_hmac');
			$table->addIndex(['last_seen_at'], 'ids_kd_last_seen');
		}

		if (!$schema->hasTable('ids_login_history')) {
			$table = $schema->createTable('ids_login_history');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('ip', Types::STRING, ['notnull' => false, 'length' => 45]);
			$table->addColumn('net_key', Types::STRING, ['notnull' => false, 'length' => 64]);
			// Control characters removed, at most 200 characters.
			$table->addColumn('user_agent', Types::STRING, ['notnull' => false, 'length' => 200]);
			// password, client_password, app_password, token, cookie or sso.
			$table->addColumn('method', Types::STRING, ['notnull' => true, 'length' => 16]);
			$table->addColumn('known_device', Types::BOOLEAN, ['notnull' => false, 'default' => false]);
			// none, second_factor, email_code, known_device or admin_approval.
			$table->addColumn('confirmed_by', Types::STRING, ['notnull' => true, 'length' => 16]);
			// Null when no extra confirmation was needed; otherwise pending, confirmed, allowed, refused or failed.
			$table->addColumn('step_up', Types::STRING, ['notnull' => false, 'length' => 16]);
			// The session token, or the app password the login used; set on the first request of a browser session.
			$table->addColumn('session_token_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->setPrimaryKey(['id']);
			$table->addIndex(['uid', 'created_at'], 'ids_lh_uid_created');
			$table->addIndex(['ip', 'created_at'], 'ids_lh_ip_created');
			$table->addIndex(['net_key', 'created_at'], 'ids_lh_net_created');
			$table->addIndex(['created_at'], 'ids_lh_created');
		}

		return $schema;
	}
}
