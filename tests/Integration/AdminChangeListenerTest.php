<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\WatchedSettings;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChangeFacts;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Event\SettingChangedEvent;
use OCA\IntrusionDetection\Event\TypedEvents;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\Notification\AdminRecipients;
use OCA\IntrusionDetection\Notification\Db\AlertMapper;
use OCA\IntrusionDetection\Notification\MailContent;
use OCA\IntrusionDetection\Notification\MailQueue;
use OCA\IntrusionDetection\Notification\MailReach;
use OCA\IntrusionDetection\Notification\Mails;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Response\Handlers\NotifyAdminHandler;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCP\App\Events\AppDisableEvent;
use OCP\App\Events\AppEnableEvent;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Group\Events\SubAdminAddedEvent;
use OCP\Group\Events\UserRemovedEvent;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Notification\IManager as INotificationManager;
use OCP\Notification\INotification;
use OCP\Server;
use OCP\User\Events\UserCreatedEvent;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Each source of the admin change check, its severity and who is told
 * (concept section 10.15).
 */
#[Group('DB')]
class AdminChangeListenerTest extends AdminChangeTestCase {
	public function testAnAdminGrantIsHighAndEveryAdminIsToldIncludingTheActor(): void {
		$this->act($this->alice);
		$this->addAsWeb('admin', $this->bob);

		$this->assertTrue($this->inGroup('admin', $this->bob), 'Without approval nothing is taken back');
		[$detection] = $this->adminChanges();
		$this->assertSame(Severity::High->value, $detection->getSeverity());
		$this->assertSame($this->bob, $detection->getUid());
		$this->assertNull($detection->getIp(), 'The actor is not an attacking address');
		$facts = $this->facts($detection);
		$this->assertSame(AdminChange::KIND_ADMIN_GRANTED, $facts['kind']);
		$this->assertSame($this->alice, $facts['actor']);
		$this->assertSame('admin', $facts['group']);
		$this->assertTrue($detection->isEnforced());

		$told = array_map(static fn (INotification $n): string => $n->getUser(), $this->notificationsWithSubject(AdminAlerts::SUBJECT));
		$this->assertContains($this->alice, $told, 'The actor is told as well');
		$this->assertContains($this->carol, $told, 'An administrator without email gets the bell');

		$prepared = Server::get(Notifier::class)->prepare($this->notificationsWithSubject(AdminAlerts::SUBJECT)[0], 'en');
		$this->assertSame($this->bob . ' was made an administrator', $prepared->getParsedSubject());
		$this->assertStringContainsString($this->alice . ' made ' . $this->bob . ' an administrator.', $prepared->getParsedMessage());
	}

	public function testTheAdminGroupIsToldEvenWhenNotificationsGoElsewhere(): void {
		$this->createGroup('ids-ac-secteam');
		$this->appConfig->setValueArray(Application::APP_ID, GlobalSettings::NOTIFY_ADMIN_GROUP, ['ids-ac-secteam']);
		$this->act($this->alice);
		$this->addAsWeb('admin', $this->bob);
		$told = array_map(static fn (INotification $n): string => $n->getUser(), $this->notificationsWithSubject(AdminAlerts::SUBJECT));
		$this->assertContains($this->carol, $told);
	}

	public function testJoiningAGroupWithDelegatedAdminSettingsIsAnAdminGrant(): void {
		$this->createGroup('ids-ac-delegates');
		$qb = $this->db->getQueryBuilder();
		$qb->insert('authorized_groups')
			->values(['group_id' => $qb->createNamedParameter('ids-ac-delegates'), 'class' => $qb->createNamedParameter(\OCA\Settings\Settings\Admin\Users::class)])
			->executeStatement();
		$this->rebuild();
		$this->act($this->alice);
		$this->addAsWeb('ids-ac-delegates', $this->bob);

		[$detection] = $this->adminChanges();
		$this->assertSame(Severity::High->value, $detection->getSeverity());
		$this->assertSame(['Users'], $this->facts($detection)['delegated']);
	}

	public function testOrdinaryGroupsAreNotWatched(): void {
		$this->createGroup('ids-ac-plain');
		$this->act($this->alice);
		$this->addAsWeb('ids-ac-plain', $this->bob);
		$this->dispatch(new UserRemovedEvent($this->group('ids-ac-plain'), $this->user($this->bob)));
		$this->assertSame([], $this->adminChanges());
	}

	public function testRemovingAnAdminIsLow(): void {
		$this->act($this->alice);
		$this->dispatch(new UserRemovedEvent($this->group('admin'), $this->user($this->carol)));
		[$detection] = $this->adminChanges();
		$this->assertSame(Severity::Low->value, $detection->getSeverity());
		$this->assertSame(AdminChange::KIND_ADMIN_REMOVED, $this->facts($detection)['kind']);
	}

	public function testAGroupAdministratorIsMedium(): void {
		$this->createGroup('ids-ac-team');
		$this->act($this->alice);
		$this->dispatch(new SubAdminAddedEvent($this->group('ids-ac-team'), $this->user($this->bob)));
		[$detection] = $this->adminChanges();
		$this->assertSame(Severity::Medium->value, $detection->getSeverity());
		$this->assertSame('ids-ac-team', $this->facts($detection)['group']);
		$this->assertSame($this->bob . ' was made a group administrator of "ids-ac-team"', Server::get(AdminAlerts::class)->headline($detection, $this->l()));
	}

	public function testAccountsCreatedByAnAdminOrOccAreLowAndThePasswordIsNeverKept(): void {
		$this->act($this->alice);
		$this->dispatch(new UserCreatedEvent($this->user($this->dave), 'Created-Password-9c9c'));
		$this->act(ActorResolver::OCC, true, true);
		$this->dispatch(new UserCreatedEvent($this->user($this->bob), 'Created-Password-9c9c'));

		$changes = $this->adminChanges();
		$this->assertCount(2, $changes);
		$this->assertSame(Severity::Low->value, $changes[0]->getSeverity());
		$this->assertSame($this->alice, $this->facts($changes[0])['actor']);
		$this->assertSame(ActorResolver::OCC, $this->facts($changes[1])['actor']);
		foreach ($this->allRows('ids_detections') as $row) {
			$this->assertStringNotContainsString('Created-Password-9c9c', json_encode($row, JSON_THROW_ON_ERROR));
		}
	}

	public function testAccountsCreatedByOthersAreNotReported(): void {
		$this->act($this->dave);
		$this->dispatch(new UserCreatedEvent($this->user($this->bob), 'x'));
		$this->act(ActorResolver::UNKNOWN);
		$this->dispatch(new UserCreatedEvent($this->user($this->bob), 'x'));
		$this->act(ActorResolver::CRON, true);
		$this->dispatch(new UserCreatedEvent($this->user($this->bob), 'x'));
		$this->assertSame([], $this->adminChanges());
	}

	public function testAppsSwitchedOnOrOffAreMediumAndThisAppOffIsHigh(): void {
		$this->act($this->alice);
		$this->dispatch(new AppEnableEvent('files_external', ['ids-ac-team']));
		$this->dispatch(new AppDisableEvent('files_external'));
		$this->dispatch(new AppDisableEvent(Application::APP_ID));

		[$enabled, $disabled, $self] = $this->adminChanges();
		$this->assertSame(Severity::Medium->value, $enabled->getSeverity());
		$this->assertSame(['ids-ac-team'], $this->facts($enabled)['groups']);
		$this->assertSame(Severity::Medium->value, $disabled->getSeverity());
		$this->assertSame(Severity::High->value, $self->getSeverity());
		$this->assertSame(Application::APP_ID, AdminChangeFacts::fromArray($this->facts($self))->app);
	}

	public function testSwitchingThisAppOffIsToldAtOnceByMeansThatOutliveIt(): void {
		$sent = [];
		$mails = $this->createMock(Mails::class);
		$mails->method('send')->willReturnCallback(static function (IUser $user, MailContent $content) use (&$sent): bool {
			$sent[$user->getUID()] = $content->subject;
			return true;
		});
		$alerts = new AdminAlerts(
			Server::get(AlertMapper::class),
			Server::get(AdminRecipients::class),
			Server::get(INotificationManager::class),
			$mails,
			$this->appSettings(),
			Server::get(NarrativeBuilder::class),
			Server::get(CheckRegistry::class),
			Server::get(UserMessages::class),
			Server::get(AdminLinks::class),
			Server::get(ITimeFactory::class),
			Server::get(MailQueue::class),
			Server::get(MailReach::class),
		);
		$this->rebuild(engine: new ResponseEngine(
			Server::get(CheckRegistry::class),
			$this->checkSettings(),
			Server::get(DetectionService::class),
			new OverridingContainer([NotifyAdminHandler::class => new NotifyAdminHandler($alerts)]),
			Server::get(TypedEvents::class),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
		));
		$this->act($this->alice);
		$this->dispatch(new AppDisableEvent(Application::APP_ID));

		$this->assertSame([$this->alice => 'Intrusion detection: The app "intrusion_detection" was switched off'], $sent, 'Sent at once, not queued for a job that stops with the app');
		$this->assertSame([], $this->queuedMails());
		$this->assertSame([], $this->notificationsWithSubject(AdminAlerts::SUBJECT), 'The app\'s own notifier stops with it');
		$bells = $this->notificationsWithSubject(AdminAlerts::OUTLIVING_SUBJECT);
		$told = array_map(static fn (INotification $n): string => $n->getUser(), $bells);
		$this->assertContains($this->alice, $told);
		$this->assertContains($this->carol, $told);
		foreach ($bells as $bell) {
			$this->assertSame(AdminAlerts::OUTLIVING_APP, $bell->getApp());
			$this->assertSame('The app "intrusion_detection" was switched off', $bell->getSubjectParameters()['subject']);
			$this->assertStringContainsString('switched off the app "intrusion_detection"', $bell->getMessageParameters()['message']);
		}
	}

	public function testSwitchingAnotherAppOffIsQueuedAsUsual(): void {
		$this->act($this->alice);
		$this->dispatch(new AppDisableEvent('files_external'));
		$this->assertNotSame([], $this->notificationsWithSubject(AdminAlerts::SUBJECT));
		$this->assertSame([], $this->notificationsWithSubject(AdminAlerts::OUTLIVING_SUBJECT));
	}

	public function testDifferentChangesAreToldSeparatelyAndRepeatsAggregated(): void {
		$this->act($this->alice);
		$this->dispatch(new AppEnableEvent('files_external'));
		$this->dispatch(new AppEnableEvent('user_ldap'));
		$this->dispatch(new AppDisableEvent('files_external'));
		$this->assertCount(3, $this->adminChanges(), 'One detection per change');
		$perAdmin = array_filter($this->notificationsWithSubject(AdminAlerts::SUBJECT), fn (INotification $n): bool => $n->getUser() === $this->carol);
		$this->assertCount(2, $perAdmin, 'One bell per kind of change and hour');
	}

	public function testOwnSettingsChangedThroughTheAppAreToldWithTheActor(): void {
		$this->act($this->alice);
		$this->dispatch(new SettingChangedEvent(Keys::mode('credential_stuffing'), 'protect', 'observe'));
		[$detection] = $this->adminChanges();
		$facts = $this->facts($detection);
		$this->assertSame(Severity::High->value, $detection->getSeverity());
		$this->assertSame($this->alice, $facts['actor']);
		$this->assertSame('protect', $facts['old']);
		$this->assertSame('observe', $facts['new']);
		$this->assertFalse($facts['watch']);
	}

	public function testSwitchingTheAppOffIsStillTold(): void {
		$this->appConfig->setValueBool(Application::APP_ID, GlobalSettings::ENABLED, false);
		$this->act($this->alice);
		$this->dispatch(new SettingChangedEvent(GlobalSettings::ENABLED, true, false));
		[$detection] = $this->adminChanges();
		$this->assertSame(Severity::High->value, $detection->getSeverity());
		$this->assertTrue($detection->isEnforced());
		$this->assertNotSame([], $this->notificationsWithSubject(AdminAlerts::SUBJECT));
	}

	public function testSwitchingThisCheckOffIsStillTold(): void {
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode(AdminChange::ID), Mode::Off->value);
		$this->act($this->alice);
		$this->dispatch(new SettingChangedEvent(Keys::mode(AdminChange::ID), 'protect', 'off'));
		$this->assertCount(1, $this->adminChanges());
	}

	public function testNothingIsRecordedWhileTheCheckIsOff(): void {
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode(AdminChange::ID), Mode::Off->value);
		$this->act($this->alice);
		$this->addAsWeb('admin', $this->bob);
		$this->dispatch(new AppEnableEvent('files_external'));
		$this->dispatch(new SettingChangedEvent(GlobalSettings::BAN_NET_AFTER, 3, 4));
		$this->assertSame([], $this->adminChanges());
	}

	public function testDuringLearningModeAdminsAreStillNotified(): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 3600);
		$this->act($this->alice);
		$this->dispatch(new AppEnableEvent('files_external'));
		[$detection] = $this->adminChanges();
		$this->assertTrue($detection->isEnforced());
		$this->assertNotSame([], $this->notificationsWithSubject(AdminAlerts::SUBJECT));
	}

	public function testDeletingAnAdministratorIsOneDetection(): void {
		$uid = 'ids-ac-deleted-' . bin2hex(random_bytes(3));
		$user = Server::get(IUserManager::class)->createUser($uid, 'Ids-Test-Password-2026');
		$this->assertNotFalse($user);
		$this->group('admin')->addUser($user);
		$this->assertTrue($user->delete());
		$removed = array_values(array_filter(
			$this->adminChanges(),
			fn ($d): bool => $this->facts($d)['kind'] === AdminChange::KIND_ADMIN_REMOVED,
		));
		$this->assertCount(1, $removed, 'Core reports the removal from the group twice when an account is deleted');
	}

	public function testRemovingAgainAfterAnotherAdditionIsReportedAgain(): void {
		$this->act($this->alice);
		$group = $this->group('admin');
		$bob = $this->user($this->bob);
		$this->dispatch(new UserRemovedEvent($group, $bob));
		$this->dispatch(new UserRemovedEvent($group, $bob));
		$this->addAsWeb('admin', $this->bob);
		$this->dispatch(new UserRemovedEvent($group, $bob));
		$kinds = array_map(fn ($d): string => $this->facts($d)['kind'], $this->adminChanges());
		$this->assertSame(2, count(array_keys($kinds, AdminChange::KIND_ADMIN_REMOVED, true)));
	}

	public function testTheWholeChainThroughSettingsAndTheRegisteredListener(): void {
		$this->settingsEditor()->setParam('credential_stuffing', 'window', 900);
		$changes = $this->adminChanges();
		$this->assertCount(1, $changes);
		$facts = $this->facts($changes[0]);
		$this->assertSame(WatchedSettings::ownKey(Keys::param('credential_stuffing', 'window')), $facts['setting']);
		$this->assertSame(600, $facts['old']);
		$this->assertSame(900, $facts['new']);
		$this->assertSame(ActorResolver::CRON, $facts['actor'], 'Tests run on the command line');
	}

	private function l(): \OCP\IL10N {
		return Server::get(IFactory::class)->get(Application::APP_ID, 'en');
	}

	/**
	 * @return list<array<string, mixed>>
	 */
	private function allRows(string $table): array {
		$result = $this->db->getQueryBuilder()->select('*')->from($table)->executeQuery();
		$rows = $result->fetchAll();
		$result->closeCursor();
		return $rows;
	}
}
