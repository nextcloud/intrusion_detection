<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCP\IAppConfig;
use OCP\IDBConnection;
use OCP\Server;
use Test\TestCase;

/**
 * Runs against the real database, with every table of the app emptied and
 * the app's settings back at their defaults (learning mode off).
 */
abstract class IntegrationTestCase extends TestCase {
	/** Tables emptied before and after each test */
	public const TABLES = ['ids_attempts', 'ids_logins', 'ids_detections', 'ids_bans', 'ids_flags'];

	protected IDBConnection $db;
	protected IAppConfig $appConfig;

	protected function setUp(): void {
		parent::setUp();
		$this->db = Server::get(IDBConnection::class);
		$this->appConfig = Server::get(IAppConfig::class);
		$this->reset();
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, 0);
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
