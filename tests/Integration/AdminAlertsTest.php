<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\Notification\AdminRecipients;
use OCA\IntrusionDetection\Notification\MailContent;
use OCA\IntrusionDetection\Notification\Mails;
use OCA\IntrusionDetection\Notification\Notifier;
use OCP\AppFramework\Utility\ITimeFactory;
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
			Server::get(Settings::class),
			Server::get(NarrativeBuilder::class),
			Server::get(CheckRegistry::class),
			Server::get(IFactory::class),
			Server::get(AdminLinks::class),
			Server::get(ITimeFactory::class),
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

	public function testAnotherSourceIsAnotherNotification(): void {
		$this->alerts->alert($this->detection('198.51.100.7'));
		$this->alerts->alert($this->detection('198.51.100.8'));
		$this->assertCount(4, $this->sent);
	}

	public function testSevereDetectionsAreEmailedOncePerCheckAndHour(): void {
		$first = $this->alerts->alert($this->detection('198.51.100.7', Severity::High));
		$second = $this->alerts->alert($this->detection('198.51.100.8', Severity::Critical));
		$this->assertSame(AdminAlerts::EMAIL_SENT, $first['email']);
		$this->assertSame(AdminAlerts::EMAIL_LIMITED, $second['email']);
		// bob has no email address: he only gets the bell.
		$this->assertSame(['alice'], array_column($this->mailed, 0));
		$this->assertCount(4, $this->sent);

		$content = $this->mailed[0][1];
		$this->assertSame('Intrusion detection: Credential stuffing from 198.51.100.7', $content->subject);
		$this->assertStringContainsString('#detection-', (string)$content->buttonUrl);
		$this->assertNotSame([], $content->listItems);
	}

	public function testLessSevereDetectionsAreNotEmailed(): void {
		$result = $this->alerts->alert($this->detection('198.51.100.7', Severity::Medium));
		$this->assertSame(AdminAlerts::EMAIL_BELOW_SEVERITY, $result['email']);
		$this->assertSame([], $this->mailed);
	}

	public function testTheEmailSeverityIsASetting(): void {
		Server::get(Settings::class)->setGlobal(GlobalSettings::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY, 'medium');
		$this->assertSame(AdminAlerts::EMAIL_SENT, $this->alerts->alert($this->detection('198.51.100.7', Severity::Medium))['email']);
		Server::get(Settings::class)->setGlobal(GlobalSettings::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY, 'never');
		$this->assertSame(AdminAlerts::EMAIL_BELOW_SEVERITY, $this->alerts->alert($this->detection('198.51.100.9', Severity::Critical))['email']);
	}

	public function testAdminsWithoutEmailGetTheBellOnly(): void {
		$recipients = $this->createMock(AdminRecipients::class);
		$recipients->method('users')->willReturn([$this->admin('carol', null)]);
		$alerts = new AdminAlerts(
			Server::get(AlertMapper::class), $recipients, $this->notifications, $this->mails, Server::get(Settings::class),
			Server::get(NarrativeBuilder::class), Server::get(CheckRegistry::class), Server::get(IFactory::class),
			Server::get(AdminLinks::class), Server::get(ITimeFactory::class),
		);
		$result = $alerts->alert($this->detection('198.51.100.7', Severity::Critical));
		$this->assertSame(AdminAlerts::EMAIL_NO_ADDRESS, $result['email']);
		$this->assertCount(1, $this->sent);
		$this->assertSame([], $this->mailed);
		// The email slot is not used up, so the next admin with an address still gets one.
		$this->assertSame(AdminAlerts::EMAIL_SENT, $this->alerts->alert($this->detection('198.51.100.8', Severity::Critical))['email']);
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
