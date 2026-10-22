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
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Learning\LearningLimitException;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Repair\ReserveSuggestedNames;
use OCA\IntrusionDetection\Repair\StartLearningMode;
use OCA\IntrusionDetection\Traps\ReservedNames;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use OCP\Migration\IOutput;
use OCP\Notification\IManager as INotificationManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Settings the app changes on its own, and an earlier end of the learning
 * period, are no administration changes: they are written to the audit
 * log. An administrator moving the end of learning mode to a later date
 * is: high when the instance was protecting, medium while learning. The app's own listener sees them here
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
		Server::get(ReserveSuggestedNames::class)->run($this->createMock(IOutput::class));
		Server::get(StartLearningMode::class)->run($this->createMock(IOutput::class));
		$reserved = Server::get(ReservedNames::class)->list();
		$this->assertNotSame([], $reserved);
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
			'Intrusion detection: reserved names ' . implode(', ', $reserved) . ' added at installation',
			'Intrusion detection: learning mode started for 7 days at installation',
			'Intrusion detection: learning mode ended automatically; protection is active',
		], self::$audit);
	}

	public function testEveryLaterEndByAnAdministratorIsAnAdministrationChange(): void {
		$watch = Server::get(ConfigWatch::class);
		$watch->run();
		$learning = Server::get(LearningService::class);
		$learning->start(7, $this->alice);

		$changes = $this->adminChanges();
		$this->assertCount(1, $changes);
		$this->assertSame(WatchedSettings::ownKey(GlobalSettings::LEARNING_UNTIL), $this->facts($changes[0])['setting']);
		$this->assertSame(Severity::High->value, $changes[0]->getSeverity(), 'Protection was on before');
		$this->assertTrue($changes[0]->isEnforced(), 'Told although learning mode is on now');
		$this->assertNotSame([], CapturingNotificationApp::$notifications, 'The administrators are notified');

		// A later end while learning keeps protection off for longer.
		$learning->extend(3, 'occ');
		$learning->start(14, $this->carol);
		$this->assertSame([Severity::High->value, Severity::Medium->value, Severity::Medium->value], $this->severities());

		// An earlier end, and the end itself, weaken nothing.
		$learning->start(2, $this->carol);
		$learning->stop($this->carol);
		$this->assertCount(3, $this->adminChanges());
		$this->assertSame(0, $watch->run(), 'The watch does not report any of them again');
		$this->assertSame([
			'Intrusion detection: learning mode started for 7 days by ' . $this->alice,
			'Intrusion detection: learning mode extended by 3 days by occ',
			'Intrusion detection: learning mode started for 14 days by ' . $this->carol,
			'Intrusion detection: learning mode started for 2 days by ' . $this->carol,
			'Intrusion detection: learning mode ended by ' . $this->carol,
		], array_values(array_filter(self::$audit, static fn (string $m): bool => !str_contains($m, 'admin_change detected'))));
	}

	public function testOneLearningPeriodLastsAtMostThirtyDaysFromItsStart(): void {
		$started = time() - 10 * 86400;
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_STARTED_AT, $started);
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);
		$learning = Server::get(LearningService::class);

		$learning->start(7, $this->alice);
		$this->assertSame($started, Server::get(Settings::class)->getInt(GlobalSettings::LEARNING_STARTED_AT), 'Starting again keeps the period\'s start');
		$this->assertSame($started + 30 * 86400, $learning->latestUntil());
		$learning->extend(13, $this->alice);
		$this->assertSame($started + 30 * 86400, $learning->until(), 'Up to the limit');

		foreach ([static fn () => $learning->extend(1, 'occ'), static fn () => $learning->start(25, 'occ')] as $change) {
			try {
				$change();
				$this->fail('More than 30 days in all');
			} catch (LearningLimitException $e) {
				$this->assertSame($started + 30 * 86400, $e->latest);
				$this->assertStringContainsString('at most 30 days in all', $e->getMessage());
			}
		}
		$this->assertSame($started + 30 * 86400, $learning->until());

		// After the end, a new period has its own start.
		$learning->stop('occ');
		$learning->start(30, 'occ');
		$this->assertEqualsWithDelta(time(), Server::get(Settings::class)->getInt(GlobalSettings::LEARNING_STARTED_AT), 5);
	}

	/**
	 * @return list<string> the severities of the admin changes, oldest first
	 */
	private function severities(): array {
		$changes = $this->adminChanges();
		usort($changes, static fn ($a, $b): int => $a->getId() <=> $b->getId());
		return array_map(static fn ($d): string => (string)$d->getSeverity(), $changes);
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
		Server::get(Settings::class)->setGlobal(GlobalSettings::EVENTS_INCLUDE_IP, false);
		$changes = $this->adminChanges();
		$this->assertCount(1, $changes);
		$this->assertSame(WatchedSettings::ownKey(GlobalSettings::EVENTS_INCLUDE_IP), $this->facts($changes[0])['setting']);
	}
}
