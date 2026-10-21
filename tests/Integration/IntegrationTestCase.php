<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AdminChange;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCP\IAppConfig;
use OCP\IDBConnection;
use OCP\Server;
use Test\TestCase;

/**
 * Runs against the real database, with every table of the app emptied and
 * the app's settings back at their defaults (learning mode off).
 *
 * The admin change check is switched off, as it would report every setting
 * the tests change; its own tests switch it on.
 */
abstract class IntegrationTestCase extends TestCase {
	/** Tables emptied before and after each test */
	public const TABLES = ['ids_attempts', 'ids_logins', 'ids_detections', 'ids_bans', 'ids_flags', 'ids_blocklist_ranges', 'ids_blocklist_stats', 'ids_protected_accounts', 'ids_alerts', 'ids_decoys', 'ids_reset_suppressions', 'ids_token_origin', 'ids_approvals', 'ids_config_snapshot', 'ids_trusted_networks', 'ids_step_up_sessions', 'ids_known_devices', 'ids_login_history', 'ids_security_changes', 'ids_lock_links', 'ids_user_daily', 'ids_risky_sessions', 'ids_lockdowns'];

	protected IDBConnection $db;
	protected IAppConfig $appConfig;

	protected function setUp(): void {
		parent::setUp();
		$this->db = Server::get(IDBConnection::class);
		$this->appConfig = Server::get(IAppConfig::class);
		$this->reset();
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, 0);
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode(AdminChange::ID), Mode::Off->value);
		// Checks are tested with their plain limits; the risk score has its own tests.
		$this->appConfig->setValueBool(Application::APP_ID, GlobalSettings::RISK_ENABLED, false);
	}

	protected function tearDown(): void {
		$this->reset();
		parent::tearDown();
	}

	private function reset(): void {
		foreach (static::TABLES as $table) {
			$this->db->getQueryBuilder()->delete($table)->executeStatement();
		}
		foreach ($this->appConfig->getKeys(Application::APP_ID) as $key) {
			if ($key !== 'enabled' && $key !== 'installed_version' && $key !== 'types') {
				$this->appConfig->deleteKey(Application::APP_ID, $key);
			}
		}
	}
}
