<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\BackgroundJob\AlertMailJob;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\ShareOwnerAlerts;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\State\AppState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJobList;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IAppConfig;
use OCP\IConfig;
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
	/** @var list<string>|null */
	private static ?array $tables = null;

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

	/**
	 * The arguments of the queued alert emails, oldest first.
	 *
	 * @return list<mixed>
	 */
	protected function queuedMails(): array {
		return array_column($this->alertMailJobs(), 'argument');
	}

	/**
	 * Run the queued alert email jobs as cron would, with these senders
	 * (the app's own where none is given).
	 *
	 * @return int how many jobs ran
	 */
	protected function runQueuedMails(?UserAlerts $users = null, ?AdminAlerts $admins = null, ?ShareOwnerAlerts $shareOwners = null): int {
		$jobList = Server::get(IJobList::class);
		$queued = $this->alertMailJobs();
		foreach ($queued as ['id' => $id, 'argument' => $argument]) {
			$job = new AlertMailJob(
				Server::get(ITimeFactory::class),
				Server::get(DetectionMapper::class),
				$users ?? Server::get(UserAlerts::class),
				$admins ?? Server::get(AdminAlerts::class),
				$shareOwners ?? Server::get(ShareOwnerAlerts::class),
			);
			$job->setId($id);
			$job->setArgument($argument);
			$job->start($jobList);
		}
		return count($queued);
	}

	/**
	 * The job list builds every job of a class on one shared instance, so
	 * each one's id and argument are read as it comes.
	 *
	 * @return list<array{id: string, argument: mixed}>
	 */
	private function alertMailJobs(): array {
		$jobs = [];
		foreach (Server::get(IJobList::class)->getJobsIterator(AlertMailJob::class, null, 0) as $job) {
			$jobs[] = ['id' => (string)$job->getId(), 'argument' => $job->getArgument()];
		}
		usort($jobs, static fn (array $a, array $b): int => (int)$a['id'] <=> (int)$b['id']);
		return $jobs;
	}

	protected function checkSettings(): CheckSettings {
		return Server::get(CheckSettings::class);
	}

	protected function appSettings(): AppSettings {
		return Server::get(AppSettings::class);
	}

	protected function settingsEditor(): SettingsEditor {
		return Server::get(SettingsEditor::class);
	}

	/**
	 * The check settings and their editor of a server with these prerequisites.
	 *
	 * @return array{CheckSettings, SettingsEditor}
	 */
	protected function settingsOn(Prerequisites $prerequisites): array {
		$appConfig = Server::get(IAppConfig::class);
		$checks = new CheckSettings($appConfig, $this->appSettings(), $prerequisites);
		return [$checks, new SettingsEditor($appConfig, $checks, $this->appSettings(), Server::get(CheckRegistry::class), $prerequisites, Server::get(GlobalSettings::class), Server::get(IEventDispatcher::class), Server::get(AppState::class))];
	}

	/**
	 * The app's tables, read from the database schema, without the table
	 * prefix. Each test starts and ends with all of them empty.
	 *
	 * @return list<string>
	 */
	public static function tables(): array {
		if (self::$tables === null) {
			$prefix = Server::get(IConfig::class)->getSystemValueString('dbtableprefix', 'oc_');
			self::$tables = [];
			foreach (Server::get(IDBConnection::class)->createSchema()->getTables() as $table) {
				$name = substr($table->getName(), strlen($prefix));
				if (str_starts_with($table->getName(), $prefix . 'ids_')) {
					self::$tables[] = $name;
				}
			}
			sort(self::$tables);
		}
		return self::$tables;
	}

	private function reset(): void {
		Server::get(IJobList::class)->remove(AlertMailJob::class);
		foreach (self::tables() as $table) {
			$this->db->getQueryBuilder()->delete($table)->executeStatement();
		}
		// What the services remember in the memory cache would outlive a test.
		Server::get(Caches::class)->clear();
		foreach ($this->appConfig->getKeys(Application::APP_ID) as $key) {
			if ($key !== 'enabled' && $key !== 'installed_version' && $key !== 'types') {
				$this->appConfig->deleteKey(Application::APP_ID, $key);
			}
		}
	}
}
