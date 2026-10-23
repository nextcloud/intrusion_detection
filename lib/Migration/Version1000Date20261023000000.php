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
 * The app's tables.
 *
 * Fingerprints are stored as lower-case hex strings (32 characters for 16
 * bytes, 64 for a keyed fingerprint), so equality lookups and indexes behave
 * the same on every database; secrets, session ids and tokens are never
 * stored, only their keyed fingerprints. Addresses of the blocklists are 32
 * lower-case hex characters (16 bytes, IPv4 as IPv4-mapped), so string order
 * is address order on every database.
 */
#[CreateTable(table: 'ids_attempts', description: 'Failed login, share and reset attempts, kept for one hour')]
#[CreateTable(table: 'ids_logins', description: 'Which accounts logged in from which address per hour, kept for one day')]
#[CreateTable(table: 'ids_detections', description: 'Detections with their explanation and the actions taken')]
#[CreateTable(table: 'ids_bans', description: 'Blocked addresses and networks')]
#[CreateTable(table: 'ids_flags', description: 'Flagged addresses and passwords that need extra confirmation')]
#[CreateTable(table: 'ids_protected_accounts', description: 'Accounts whose password logins need extra confirmation for a while')]
#[CreateTable(table: 'ids_alerts', description: 'Hourly counters per check and source that aggregate admin notifications and emails')]
#[CreateTable(table: 'ids_decoys', description: 'Decoy credentials planted by administrators, stored as keyed fingerprints')]
#[CreateTable(table: 'ids_token_origin', description: 'The session and address each app password was created from, kept for 30 days')]
#[CreateTable(table: 'ids_trusted_networks', description: 'Networks a user confirmed as their own by answering "Yes, it was me", kept for 30 days')]
#[CreateTable(table: 'ids_step_up_sessions', description: 'Fingerprints of sessions whose login was not confirmed, kept while the session could be resumed')]
#[CreateTable(table: 'ids_reset_suppressions', description: 'Accounts whose password reset emails are not sent for a while, because someone requested too many')]
#[CreateTable(table: 'ids_blocklist_ranges', description: 'Address ranges of the downloaded blocklists and network attribute lists')]
#[CreateTable(table: 'ids_blocklist_stats', description: 'Per list and day: how often an address on the list was looked up, and the last matched addresses')]
#[CreateTable(table: 'ids_known_devices', description: 'Keyed fingerprints of the device cookies of browsers a user chose to remember, kept until 180 days after their last use')]
#[CreateTable(table: 'ids_login_history', description: 'One row per successful login: when, from where, with which client and how it was confirmed, kept 90 days')]
#[CreateTable(table: 'ids_security_changes', description: 'Security changes of accounts: email, password, second factor, app passwords and connected devices')]
#[CreateTable(table: 'ids_lock_links', description: 'One-time links that let the previous email address lock an account')]
#[CreateTable(table: 'ids_approvals', description: 'Requests that need the approval of a second administrator, such as making someone an administrator')]
#[CreateTable(table: 'ids_config_snapshot', description: 'Keyed hashes and display values of the watched security settings, to find changes')]
#[CreateTable(table: 'ids_user_daily', description: 'Failed logins per account and day (UTC), split by hour, with up to 20 addresses they came from, kept 30 days')]
#[CreateTable(table: 'ids_detection_accounts', description: 'Which accounts each detection is about or mentions, for deleting accounts and for incident reports')]
#[CreateTable(table: 'ids_detection_hourly', description: 'Detections per hour, check, severity and enforcement, for the statistics and the metrics')]
#[CreateTable(table: 'ids_state', description: 'Internal state written often: the verdict cache version, the firewall export state')]
class Version1000Date20261023000000 extends SimpleMigrationStep {
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
			// How many attempts the row stands for: more than one while a flood is sampled.
			$table->addColumn('weight', Types::SMALLINT, ['notnull' => true, 'unsigned' => true, 'default' => 1]);
			// True when the attempt may have been a lure (a request a browser made for another site); null otherwise.
			$table->addColumn('lure', Types::BOOLEAN, ['notnull' => false, 'default' => null]);
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
			// The batched cleanup reads in this order, so that a batch starts where the last one ended within an hour of many rows.
			$table->addIndex(['hour', 'id'], 'ids_login_hour_id');
			$table->addIndex(['uid'], 'ids_login_uid');
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
			// The address risk score: recent detections of an IPv6 /64. Merged detections stay open, so the lookup is by last_seen_at.
			$table->addIndex(['net_key', 'last_seen_at'], 'ids_det_net_seen');
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
			$table->addIndex(['created_at'], 'ids_ban_created');
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

		if (!$schema->hasTable('ids_protected_accounts')) {
			$table = $schema->createTable('ids_protected_accounts');
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('reason', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->addColumn('detection_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('expires_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['uid']);
			$table->addIndex(['expires_at'], 'ids_prot_expires');
		}

		if (!$schema->hasTable('ids_alerts')) {
			$table = $schema->createTable('ids_alerts');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('check_id', Types::STRING, ['notnull' => true, 'length' => 32]);
			// An ip key, "u:" plus a uid, "instance", or "@mail" for the email limit.
			$table->addColumn('source_key', Types::STRING, ['notnull' => true, 'length' => 80]);
			// The hour (Unix time / 3600) the counter belongs to.
			$table->addColumn('bucket', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('hits', Types::INTEGER, ['notnull' => true, 'unsigned' => true, 'default' => 1]);
			$table->addColumn('detection_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('first_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('last_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			// How many administrators the first notification of the hour went to.
			$table->addColumn('recipients', Types::INTEGER, ['notnull' => false, 'unsigned' => true]);
			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['check_id', 'source_key', 'bucket'], 'ids_alert_uniq');
			$table->addIndex(['last_at'], 'ids_alert_last');
			// The unique index starts with check_id, so it does not serve a lookup by source_key alone.
			$table->addIndex(['source_key'], 'ids_alert_src');
		}

		if (!$schema->hasTable('ids_decoys')) {
			$table = $schema->createTable('ids_decoys');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('login_name', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('secret_hmac', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('format', Types::STRING, ['notnull' => true, 'length' => 16]);
			$table->addColumn('label', Types::STRING, ['notnull' => true, 'length' => 200]);
			$table->addColumn('created_by', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('last_triggered_at', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('trigger_count', Types::INTEGER, ['notnull' => true, 'unsigned' => true, 'default' => 0]);
			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['secret_hmac'], 'ids_decoy_secret');
			$table->addIndex(['login_name'], 'ids_decoy_login');
		}

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
			// Hex of a SHA-256 digest of the session id; never the session id itself.
			$table->addColumn('session_key', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('expires_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			// Until when a pending login may wait for its confirmation, or a refused login keeps its session; null once ended.
			$table->addColumn('deadline', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('ip', Types::STRING, ['notnull' => false, 'length' => 45]);
			// Why the pending login needs confirmation, comma separated.
			$table->addColumn('policies', Types::STRING, ['notnull' => false, 'length' => 255]);
			// The email code tries, counted here so that parallel requests cannot share one count in the PHP session.
			$table->addColumn('attempts', Types::INTEGER, ['notnull' => true, 'default' => 0, 'unsigned' => true]);
			// 1 when the login was refused, 0 when it waits for its confirmation.
			$table->addColumn('refused', Types::SMALLINT, ['notnull' => true, 'default' => 0, 'unsigned' => true]);
			$table->setPrimaryKey(['session_key']);
			$table->addIndex(['uid'], 'ids_sus_uid');
			$table->addIndex(['expires_at'], 'ids_sus_expires');
			$table->addIndex(['deadline'], 'ids_sus_deadline');
		}

		if (!$schema->hasTable('ids_reset_suppressions')) {
			$table = $schema->createTable('ids_reset_suppressions');
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('detection_id', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('expires_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['uid']);
			$table->addIndex(['expires_at'], 'ids_rsup_expires');
		}

		if (!$schema->hasTable('ids_blocklist_ranges')) {
			$table = $schema->createTable('ids_blocklist_ranges');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('list_id', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->addColumn('version', Types::INTEGER, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('family', Types::SMALLINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('range_start', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->addColumn('range_end', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->setPrimaryKey(['id']);
			// The lookup is "the last range of this list version that starts at or
			// below the address": equality on the first three columns, then a
			// backwards range scan that stops at the first row. The same index
			// serves deleting a whole version.
			$table->addIndex(['list_id', 'version', 'family', 'range_start'], 'ids_blr_lookup');
		}

		if (!$schema->hasTable('ids_blocklist_stats')) {
			$table = $schema->createTable('ids_blocklist_stats');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('list_id', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->addColumn('day', Types::STRING, ['notnull' => true, 'length' => 10]);
			$table->addColumn('matches', Types::BIGINT, ['notnull' => true, 'unsigned' => true, 'default' => 0]);
			$table->addColumn('sample', Types::TEXT, ['notnull' => false]);
			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['list_id', 'day'], 'ids_bls_day');
		}

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

		if (!$schema->hasTable('ids_approvals')) {
			$table = $schema->createTable('ids_approvals');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('kind', Types::STRING, ['notnull' => true, 'length' => 16]);
			$table->addColumn('subject_uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			// A uid, or "occ", "cron" or "unknown" when no user made the request.
			$table->addColumn('requested_by', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('group_id', Types::STRING, ['notnull' => false, 'length' => 255]);
			$table->addColumn('ip', Types::STRING, ['notnull' => false, 'length' => 45]);
			$table->addColumn('status', Types::STRING, ['notnull' => true, 'length' => 16]);
			$table->addColumn('decided_by', Types::STRING, ['notnull' => false, 'length' => 64]);
			$table->addColumn('created_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('decided_at', Types::BIGINT, ['notnull' => false, 'unsigned' => true]);
			$table->addColumn('expires_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			// The settings change a request of the kind "settings" holds back, as JSON.
			$table->addColumn('payload', Types::TEXT, ['notnull' => false]);
			$table->setPrimaryKey(['id']);
			$table->addIndex(['status', 'expires_at'], 'ids_appr_status');
			$table->addIndex(['subject_uid', 'status'], 'ids_appr_subject');
		}

		if (!$schema->hasTable('ids_config_snapshot')) {
			$table = $schema->createTable('ids_config_snapshot');
			// "system:<config.php key>" or "app:<app id>:<key>".
			$table->addColumn('setting_key', Types::STRING, ['notnull' => true, 'length' => 128]);
			// A keyed hash of the value, so that a change is found without storing the value.
			$table->addColumn('value_hash', Types::STRING, ['notnull' => true, 'length' => 64]);
			// JSON of the shortened value; null when the value is secret.
			$table->addColumn('display_value', Types::TEXT, ['notnull' => false]);
			$table->addColumn('updated_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['setting_key']);
		}

		if (!$schema->hasTable('ids_user_daily')) {
			$table = $schema->createTable('ids_user_daily');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			// The start of the day in UTC, as a timestamp.
			$table->addColumn('day', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('failed_logins', Types::INTEGER, ['notnull' => true, 'unsigned' => true, 'default' => 0]);
			// JSON list of 24 counts, one per hour of the day (UTC), so that pages can show the user's own days.
			$table->addColumn('hours', Types::STRING, ['notnull' => false, 'length' => 400]);
			// JSON object of up to 20 address keys and when each one last failed.
			$table->addColumn('sources', Types::TEXT, ['notnull' => false]);
			$table->addColumn('updated_at', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['uid', 'day'], 'ids_ud_uid_day');
			// The batched cleanup reads in this order, so that a batch starts where the last one ended within a day of many rows.
			$table->addIndex(['day', 'id'], 'ids_ud_day_id');
		}

		if (!$schema->hasTable('ids_detection_accounts')) {
			$table = $schema->createTable('ids_detection_accounts');
			$table->addColumn('detection_id', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('uid', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->setPrimaryKey(['detection_id', 'uid']);
			$table->addIndex(['uid', 'detection_id'], 'ids_detacc_uid');
		}

		if (!$schema->hasTable('ids_detection_hourly')) {
			$table = $schema->createTable('ids_detection_hourly');
			$table->addColumn('id', Types::BIGINT, ['autoincrement' => true, 'notnull' => true, 'unsigned' => true]);
			// Unix time / 3600 of the hour.
			$table->addColumn('hour', Types::BIGINT, ['notnull' => true, 'unsigned' => true]);
			$table->addColumn('check_id', Types::STRING, ['notnull' => true, 'length' => 32]);
			$table->addColumn('severity', Types::STRING, ['notnull' => true, 'length' => 16]);
			// 1 when Nextcloud acted on the detections, 0 when they were only observed.
			$table->addColumn('enforced', Types::SMALLINT, ['notnull' => true, 'unsigned' => true, 'default' => 0]);
			// New detections in the hour.
			$table->addColumn('created', Types::INTEGER, ['notnull' => true, 'unsigned' => true, 'default' => 0]);
			// Detections whose severity rose to this one in the hour.
			$table->addColumn('raised', Types::INTEGER, ['notnull' => true, 'unsigned' => true, 'default' => 0]);
			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['hour', 'check_id', 'severity', 'enforced'], 'ids_dh_uniq');
		}

		if (!$schema->hasTable('ids_state')) {
			$table = $schema->createTable('ids_state');
			$table->addColumn('name', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('value', Types::TEXT, ['notnull' => false]);
			$table->setPrimaryKey(['name']);
		}

		return $schema;
	}
}
