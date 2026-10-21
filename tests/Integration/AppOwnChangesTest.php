<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AdminChange\ConfigWatch;
use OCA\IntrusionDetection\AdminChange\WatchedSettings;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Repair\StartLearningMode;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use OCP\Migration\IOutput;
use OCP\Notification\IManager as INotificationManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Settings the app changes on its own, and changes of a running learning
 * period, are no administration changes: they are written to the audit
 * log. An administrator starting learning mode while the instance was
 * protecting is, with high severity. The app's own listener sees them here
 * as in production (the tests run on the command line, as cron does).
 */
#[Group('DB')]
class AppOwnChangesTest extends AdminChangeTestCase {
	/** @var list<string> audit log messages of the current test */
	private static array $audit = [];
	private static bool $listening = false;

	protected function setUp(): void {
		parent::setUp();
		if (!self::$listening) {
			Server::get(IEventDispatcher::class)->addListener(CriticalActionPerformedEvent::class, static function (CriticalActionPerformedEvent $event): void {
				self::$audit[] = vsprintf($event->getLogMessage(), $event->getParameters());
			});
			self::$listening = true;
		}
		self::$audit = [];
	}

	public function testAFreshInstallAndOneLearningPeriodAreNoAdministrationChanges(): void {
		$this->assertSame(0, Server::get(Settings::class)->getInt(GlobalSettings::INSTALLED_AT), 'A fresh install');
		Server::get(StartLearningMode::class)->run($this->createMock(IOutput::class));
		$learning = Server::get(LearningService::class);
		$this->assertTrue($learning->isActive());

		$watch = Server::get(ConfigWatch::class);
		$this->assertSame(0, $watch->run(), 'The first run records the baseline');

		// The period is over: the hourly job ends it.
		$later = $this->createMock(ITimeFactory::class);
		$later->method('getTime')->willReturn($learning->until() + 60);
		$expiring = new LearningService(Server::get(Settings::class), $later, Server::get(AuditLogger::class), Server::get(INotificationManager::class));
		$this->assertTrue($expiring->expireIfDue());
		$this->assertFalse($learning->isActive());

		$this->assertSame(0, $watch->run(), 'The watch does not find the app\'s own changes either');
		$this->assertSame([], $this->adminChanges());
		$this->assertSame([], CapturingNotificationApp::$notifications);
		$this->assertSame([
			'Intrusion detection: learning mode started for 7 days at installation',
			'Intrusion detection: learning mode ended automatically; protection is active',
		], self::$audit);
	}

	public function testAnAdministratorStartingLearningWhileProtectingIsOneHighAlert(): void {
		$watch = Server::get(ConfigWatch::class);
		$watch->run();
		$learning = Server::get(LearningService::class);
		$learning->start(7, $this->alice);

		$changes = $this->adminChanges();
		$this->assertCount(1, $changes);
		$this->assertSame(WatchedSettings::ownKey(GlobalSettings::LEARNING_UNTIL), $this->facts($changes[0])['setting']);
		$this->assertSame(Severity::High->value, $changes[0]->getSeverity());
		$this->assertTrue($changes[0]->isEnforced(), 'Told although learning mode is on now');
		$this->assertNotSame([], CapturingNotificationApp::$notifications, 'The administrators are notified');

		// Changing the running period and ending it weaken nothing.
		$learning->extend(3, 'occ');
		$learning->start(14, $this->carol);
		$learning->stop($this->carol);
		$this->assertCount(1, $this->adminChanges());
		$this->assertSame(0, $watch->run(), 'The watch does not report any of them again');
		$this->assertSame([
			'Intrusion detection: admin_change detected (high, enforced), source , account ',
			'Intrusion detection: learning mode started for 7 days by ' . $this->alice,
			'Intrusion detection: learning mode extended by 3 days by occ',
			'Intrusion detection: learning mode started for 14 days by ' . $this->carol,
			'Intrusion detection: learning mode ended by ' . $this->carol,
		], self::$audit);
	}

	public function testExtendingWhileProtectingStartsLearningAndIsOneHighAlert(): void {
		Server::get(LearningService::class)->extend(3, 'occ');
		$changes = $this->adminChanges();
		$this->assertCount(1, $changes);
		$this->assertSame(Severity::High->value, $changes[0]->getSeverity());
	}

	public function testStartingLearningModeAroundTheAppIsStillReported(): void {
		$watch = Server::get(ConfigWatch::class);
		$watch->run();
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);

		$this->assertSame(1, $watch->run());
		$changes = $this->adminChanges();
		$this->assertCount(1, $changes);
		$this->assertSame(WatchedSettings::ownKey(GlobalSettings::LEARNING_UNTIL), $this->facts($changes[0])['setting']);
		$this->assertSame(Severity::High->value, $changes[0]->getSeverity());
	}

	public function testOtherSettingsChangedThroughTheAppAreStillReported(): void {
		Server::get(Settings::class)->setGlobal(GlobalSettings::LEARNING_DECOYS_ACT, false);
		$changes = $this->adminChanges();
		$this->assertCount(1, $changes);
		$this->assertSame(WatchedSettings::ownKey(GlobalSettings::LEARNING_DECOYS_ACT), $this->facts($changes[0])['setting']);
	}
}
