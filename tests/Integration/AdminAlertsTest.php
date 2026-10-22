<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffing;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\Notification\AdminRecipients;
use OCA\IntrusionDetection\Notification\MailContent;
use OCA\IntrusionDetection\Notification\MailQueue;
use OCA\IntrusionDetection\Notification\Mails;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Response\Handlers\NotifyAdminHandler;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;
use OCP\IGroup;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Notification\IManager as INotificationManager;
use OCP\Notification\INotification;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * Aggregation of admin notifications and emails (concept section 11.1).
 */
#[Group('DB')]
class AdminAlertsTest extends IntegrationTestCase {
	/** @var INotificationManager&MockObject */
	private INotificationManager $notifications;
	/** @var Mails&MockObject */
	private Mails $mails;
	/** @var AdminRecipients&MockObject */
	private AdminRecipients $recipients;
	/** @var list<INotification> */
	private array $sent = [];
	/** @var list<array{string, MailContent}> */
	private array $mailed = [];
	private AdminAlerts $alerts;

	protected function setUp(): void {
		parent::setUp();
		$real = Server::get(INotificationManager::class);
		$this->notifications = $this->createMock(INotificationManager::class);
		$this->notifications->method('createNotification')->willReturnCallback(static fn (): INotification => $real->createNotification());
		$this->notifications->method('notify')->willReturnCallback(function (INotification $n): void {
			$this->sent[] = $n;
		});
		$this->mails = $this->createMock(Mails::class);
		$this->mails->method('send')->willReturnCallback(function (IUser $user, MailContent $content): bool {
			$this->mailed[] = [$user->getUID(), $content];
			return true;
		});
		$this->recipients = $this->createMock(AdminRecipients::class);
		$this->recipients->method('users')->willReturn([$this->admin('alice', 'alice@example.com'), $this->admin('bob', null)]);
		$this->alerts = new AdminAlerts(
			Server::get(AlertMapper::class),
			$this->recipients,
			$this->notifications,
			$this->mails,
			$this->appSettings(),
			Server::get(NarrativeBuilder::class),
			Server::get(CheckRegistry::class),
			Server::get(UserMessages::class),
			Server::get(AdminLinks::class),
			Server::get(ITimeFactory::class),
			Server::get(MailQueue::class),
		);
	}

	public function testManyHitsFromOneSourceAreOneNotificationWithACounter(): void {
		for ($i = 0; $i < 5; $i++) {
			$result = $this->alerts->alert($this->detection('198.51.100.7'));
		}
		$this->assertCount(2, $this->sent, 'One notification per admin');
		$this->assertSame(AdminAlerts::BELL_AGGREGATED, $result['bell']);
		$this->assertSame(5, $result['hits']);
		$this->assertSame(['alice', 'bob'], array_map(static fn (INotification $n): string => $n->getUser(), $this->sent));

		// The notifier shows the live counter of the aggregated alert.
		$prepared = Server::get(Notifier::class)->prepare($this->sent[0], 'en');
		$this->assertStringContainsString('This happened 5 times within the hour.', $prepared->getParsedMessage());
		$this->assertSame('Credential stuffing from 198.51.100.7', $prepared->getParsedSubject());
		$this->assertStringContainsString('/settings/admin/intrusion_detection#detection-', $prepared->getLink());
	}

	public function testAggregatedHitsDoNotLookTheAdministratorsUp(): void {
		$recipients = $this->createMock(AdminRecipients::class);
		$recipients->expects($this->once())->method('users')->willReturn([$this->admin('alice', 'alice@example.com'), $this->admin('bob', null)]);
		$alerts = new AdminAlerts(
			Server::get(AlertMapper::class), $recipients, $this->notifications, $this->mails, $this->appSettings(),
			Server::get(NarrativeBuilder::class), Server::get(CheckRegistry::class), Server::get(UserMessages::class),
			Server::get(AdminLinks::class), Server::get(ITimeFactory::class), Server::get(MailQueue::class),
		);
		// The first hit sends the bell and the email, with one lookup.
		$this->assertSame(2, $alerts->alert($this->detection('198.51.100.7', Severity::Critical))['recipients']);
		for ($i = 0; $i < 5; $i++) {
			$result = $alerts->alert($this->detection('198.51.100.7', Severity::Critical));
		}
		$this->assertSame(AdminAlerts::BELL_AGGREGATED, $result['bell']);
		$this->assertSame(AdminAlerts::EMAIL_LIMITED, $result['email']);
		$this->assertSame(2, $result['recipients'], 'the number the first hit went to');
	}

	public function testAnotherSourceIsAnotherNotification(): void {
		$this->alerts->alert($this->detection('198.51.100.7'));
		$this->alerts->alert($this->detection('198.51.100.8'));
		$this->assertCount(4, $this->sent);
	}

	public function testSevereDetectionsAreEmailedOncePerCheckAndHour(): void {
		$detection = $this->detection('198.51.100.7', Severity::High);
		$first = $this->alerts->alert($detection);
		$second = $this->alerts->alert($this->detection('198.51.100.8', Severity::Critical));
		$this->assertSame(AdminAlerts::EMAIL_QUEUED, $first['email']);
		$this->assertSame(AdminAlerts::EMAIL_LIMITED, $second['email']);
		$this->assertSame([], $this->mailed, 'Not in the request');
		$this->assertSame([['kind' => MailQueue::KIND_ADMIN, 'detection' => $detection->getId()]], $this->queuedMails(), 'One email per check and hour');
		$this->assertSame(1, $this->runQueuedMails(admins: $this->alerts));
		// bob has no email address: he only gets the bell.
		$this->assertSame(['alice'], array_column($this->mailed, 0));
		$this->assertCount(4, $this->sent);

		$content = $this->mailed[0][1];
		$this->assertSame('Intrusion detection: Credential stuffing from 198.51.100.7', $content->subject);
		$this->assertStringContainsString('#detection-', (string)$content->buttonUrl);
		$this->assertNotSame([], $content->listItems);
	}

	public function testEveryTimeInTheEmailIsInTheRecipientsTimeZone(): void {
		$config = Server::get(IUserConfig::class);
		$config->setValueString('ids-alert-tokyo', 'core', 'timezone', 'Asia/Tokyo');
		$config->setValueString('ids-alert-berlin', 'core', 'timezone', 'Europe/Berlin');
		$detection = $this->detection('198.51.100.7', Severity::Critical);
		// Monday, October 12, 2026, 08:00 to 08:05 UTC.
		$detection->setCreatedAt(1791792000);
		$detection->setLastSeenAt(1791792300);

		try {
			$tokyo = implode(' ', $this->alerts->mailFor($detection, $this->admin('ids-alert-tokyo', 'tokyo@example.com'))->paragraphs);
			$berlin = implode(' ', $this->alerts->mailFor($detection, $this->admin('ids-alert-berlin', 'berlin@example.com'))->paragraphs);
		} finally {
			$config->deleteAllUserConfig('ids-alert-tokyo');
			$config->deleteAllUserConfig('ids-alert-berlin');
		}

		// ICU puts a narrow no-break space before "PM".
		$this->assertStringContainsString('Between October 12, 2026, 5:00 PM and 5:05 PM', str_replace("\u{202F}", ' ', $tokyo));
		$this->assertStringContainsString('Between October 12, 2026, 10:00 AM and 10:05 AM', str_replace("\u{202F}", ' ', $berlin));
	}

	public function testLessSevereDetectionsAreNotEmailed(): void {
		$result = $this->alerts->alert($this->detection('198.51.100.7', Severity::Medium));
		$this->assertSame(AdminAlerts::EMAIL_BELOW_SEVERITY, $result['email']);
		$this->assertSame([], $this->mailed);
	}

	public function testTheEmailSeverityIsASetting(): void {
		$this->settingsEditor()->setGlobal(GlobalSettings::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY, 'medium');
		$this->assertSame(AdminAlerts::EMAIL_QUEUED, $this->alerts->alert($this->detection('198.51.100.7', Severity::Medium))['email']);
		$this->settingsEditor()->setGlobal(GlobalSettings::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY, 'never');
		$this->assertSame(AdminAlerts::EMAIL_BELOW_SEVERITY, $this->alerts->alert($this->detection('198.51.100.9', Severity::Critical))['email']);
	}

	public function testAdminsWithoutEmailGetTheBellOnly(): void {
		$recipients = $this->createMock(AdminRecipients::class);
		$recipients->method('users')->willReturn([$this->admin('carol', null)]);
		$alerts = new AdminAlerts(
			Server::get(AlertMapper::class), $recipients, $this->notifications, $this->mails, $this->appSettings(),
			Server::get(NarrativeBuilder::class), Server::get(CheckRegistry::class), Server::get(UserMessages::class),
			Server::get(AdminLinks::class), Server::get(ITimeFactory::class), Server::get(MailQueue::class),
		);
		$result = $alerts->alert($this->detection('198.51.100.7', Severity::Critical));
		$this->assertSame(AdminAlerts::EMAIL_NO_ADDRESS, $result['email']);
		$this->assertCount(1, $this->sent);
		$this->assertSame([], $this->mailed);
		// The email slot is not used up, so the next admin with an address still gets one.
		$this->assertSame(AdminAlerts::EMAIL_QUEUED, $this->alerts->alert($this->detection('198.51.100.8', Severity::Critical))['email']);
	}

	public function testAdminsWithoutEmailAreNotLookedUpAgainForAMinute(): void {
		$group = $this->createMock(IGroup::class);
		$group->expects($this->once())->method('searchUsers')->willReturn([$this->admin('carol', null)]);
		$groups = $this->createMock(IGroupManager::class);
		$groups->method('get')->willReturn($group);
		$cache = new ArrayCache('ids-test-recipients');
		$factory = new FixedCaches(null, $cache);
		$recipients = new AdminRecipients($this->appSettings(), $groups, $factory);
		$alerts = new AdminAlerts(
			Server::get(AlertMapper::class), $recipients, $this->notifications, $this->mails, $this->appSettings(),
			Server::get(NarrativeBuilder::class), Server::get(CheckRegistry::class), Server::get(UserMessages::class),
			Server::get(AdminLinks::class), Server::get(ITimeFactory::class), Server::get(MailQueue::class),
		);
		$this->assertSame(AdminAlerts::EMAIL_NO_ADDRESS, $alerts->alert($this->detection('198.51.100.7', Severity::Critical))['email']);
		for ($i = 0; $i < 5; $i++) {
			$this->assertSame(AdminAlerts::EMAIL_NO_ADDRESS, $alerts->alert($this->detection('198.51.100.7', Severity::Critical))['email']);
		}
	}

	public function testAnEmailThatCouldNotBeSentIsNotBlamedOnMissingAddresses(): void {
		$mails = $this->createMock(Mails::class);
		$mails->method('send')->willReturn(false);
		$alerts = new AdminAlerts(
			Server::get(AlertMapper::class), $this->recipients, $this->notifications, $mails, $this->appSettings(),
			Server::get(NarrativeBuilder::class), Server::get(CheckRegistry::class), Server::get(UserMessages::class),
			Server::get(AdminLinks::class), Server::get(ITimeFactory::class), Server::get(MailQueue::class),
		);
		$this->assertSame(AdminAlerts::EMAIL_QUEUED, $alerts->alert($this->detection('198.51.100.7', Severity::Critical))['email']);
		$this->runQueuedMails(admins: $alerts);
		$this->assertSame([], $this->queuedMails(), 'A failed email is not retried');

		$sentences = Server::get(NotifyAdminHandler::class)->describeAction(
			['type' => 'notify_admin', 'enforced' => true, 'ref' => ['email' => AdminAlerts::EMAIL_FAILED]],
			Server::get(IFactory::class)->get('intrusion_detection', 'en'),
			Server::get(DateFormatter::class),
		);
		$this->assertStringContainsString('could not be sent', implode(' ', $sentences));
		$this->assertStringNotContainsString('no administrator has an email address', implode(' ', $sentences));
	}

	public function testAPreparedNotificationOfADeletedDetectionIsDropped(): void {
		$this->alerts->alert($this->detection('198.51.100.7'));
		$this->db->getQueryBuilder()->delete('ids_detections')->executeStatement();
		$this->expectException(\OCP\Notification\AlreadyProcessedException::class);
		Server::get(Notifier::class)->prepare($this->sent[0], 'en');
	}

	private function detection(string $ip, Severity $severity = Severity::Medium): Detection {
		$detection = new Detection();
		$detection->setCheckId(CredentialStuffing::ID);
		$detection->setSeverity($severity->value);
		$detection->setEnforced(true);
		$detection->setIp($ip);
		$detection->setExplanationData(['facts' => ['rule' => 'source', 'failures' => 10, 'names' => 5], 'thresholds' => ['min_failures' => 10, 'min_names' => 5, 'window' => 600]]);
		$detection->setActionList([['type' => 'ban', 'enforced' => true]]);
		$detection->setCreatedAt(time());
		$detection->setLastSeenAt(time());
		$detection->setHits(1);
		return Server::get(DetectionMapper::class)->insert($detection);
	}

	private function admin(string $uid, ?string $email): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($uid);
		$user->method('getEMailAddress')->willReturn($email);
		$user->method('getDisplayName')->willReturn(ucfirst($uid));
		return $user;
	}
}
