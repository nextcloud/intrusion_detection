<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\Notification\AdminRecipients;
use OCA\IntrusionDetection\Notification\Db\AlertMapper;
use OCA\IntrusionDetection\Notification\MailContent;
use OCA\IntrusionDetection\Notification\MailQueue;
use OCA\IntrusionDetection\Notification\MailReach;
use OCA\IntrusionDetection\Notification\Mails;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;
use OCP\Notification\IManager as INotificationManager;
use OCP\Notification\INotification;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * How admin change alerts reach the administrators (concept sections 10.15
 * and 11.1): every administrator including the one who made the change, an
 * email for severe changes to those with an address, and aggregation per kind
 * of change rather than per check.
 */
#[Group('DB')]
class AdminChangeAlertsTest extends IntegrationTestCase {
	/** @var list<INotification> */
	private array $sent = [];
	/** @var list<array{string, MailContent}> */
	private array $mailed = [];
	private AdminAlerts $alerts;
	/** @var list<bool> what users() was asked for */
	private array $withAdminGroup = [];

	protected function setUp(): void {
		parent::setUp();
		$real = Server::get(INotificationManager::class);
		$notifications = $this->createMock(INotificationManager::class);
		$notifications->method('createNotification')->willReturnCallback(static fn (): INotification => $real->createNotification());
		$notifications->method('notify')->willReturnCallback(function (INotification $n): void {
			$this->sent[] = $n;
		});
		$mails = $this->createMock(Mails::class);
		$mails->method('send')->willReturnCallback(function (IUser $user, MailContent $content): bool {
			$this->mailed[] = [$user->getUID(), $content];
			return true;
		});
		$recipients = $this->createMock(AdminRecipients::class);
		$recipients->method('users')->willReturnCallback(function (bool $withAdminGroup = false): array {
			$this->withAdminGroup[] = $withAdminGroup;
			// alice made the change; carol has no email address.
			return [$this->admin('alice', 'alice@example.com'), $this->admin('carol', null)];
		});
		$this->alerts = new AdminAlerts(
			Server::get(AlertMapper::class), $recipients, $notifications, $mails, $this->appSettings(),
			Server::get(NarrativeBuilder::class), Server::get(CheckRegistry::class), Server::get(UserMessages::class),
			Server::get(AdminLinks::class), Server::get(ITimeFactory::class), Server::get(MailQueue::class),
			Server::get(MailReach::class),
		);
	}

	public function testEveryAdminIsToldAndOnlyThoseWithAnAddressAreEmailed(): void {
		$result = $this->alerts->alert($this->change(AdminChange::KIND_ADMIN_GRANTED, Severity::High, 'admin_granted:admin'));
		$this->assertSame([true], $this->withAdminGroup, 'The admin group is always included');
		$this->assertSame(['alice', 'carol'], array_map(static fn (INotification $n): string => $n->getUser(), $this->sent));
		$this->assertSame(AdminAlerts::EMAIL_QUEUED, $result['email']);
		$this->runQueuedMails(admins: $this->alerts);
		$this->assertSame([true, true], $this->withAdminGroup, 'The admin group is always included, also when the email is sent');
		$this->assertSame(['alice'], array_column($this->mailed, 0), 'The actor gets the email too; carol has no address');
		$this->assertSame('Intrusion detection: bob was made an administrator', $this->mailed[0][1]->subject);
	}

	public function testDifferentSevereChangesWithinTheHourAreEachEmailed(): void {
		$first = $this->alerts->alert($this->change(AdminChange::KIND_SETTING_CHANGED, Severity::High, 'setting:system:trusted_proxies'));
		$second = $this->alerts->alert($this->change(AdminChange::KIND_ADMIN_GRANTED, Severity::High, 'admin_granted:admin'));
		$this->assertSame(AdminAlerts::EMAIL_QUEUED, $first['email']);
		$this->assertSame(AdminAlerts::EMAIL_QUEUED, $second['email'], 'A new administrator is not hidden behind an earlier change');
		$this->assertSame(2, $this->runQueuedMails(admins: $this->alerts));
		$this->assertCount(2, $this->mailed);
		$this->assertCount(4, $this->sent);
	}

	public function testTheSameKindOfChangeIsAggregated(): void {
		$this->alerts->alert($this->change(AdminChange::KIND_APP_ENABLED, Severity::High, 'app_enabled'));
		$second = $this->alerts->alert($this->change(AdminChange::KIND_APP_ENABLED, Severity::High, 'app_enabled'));
		$this->assertSame(AdminAlerts::BELL_AGGREGATED, $second['bell']);
		$this->assertSame(AdminAlerts::EMAIL_LIMITED, $second['email']);
		$this->assertSame(2, $second['hits']);
		$this->assertCount(2, $this->sent);
	}

	public function testLessSevereChangesAreNotEmailed(): void {
		$this->assertSame(AdminAlerts::EMAIL_BELOW_SEVERITY, $this->alerts->alert($this->change(AdminChange::KIND_SUBADMIN_GRANTED, Severity::Medium, 'subadmin_granted'))['email']);
		$this->assertSame([], $this->mailed);
	}

	private function change(string $kind, Severity $severity, string $alertKey): Detection {
		$detection = new Detection();
		$detection->setCheckId(AdminChange::ID);
		$detection->setSeverity($severity->value);
		$detection->setEnforced(true);
		$detection->setUid('bob');
		$detection->setExplanationData(['facts' => [
			'kind' => $kind,
			'actor' => 'alice',
			'targets' => ['bob'],
			'group' => 'admin',
			'app' => 'files_external',
			'setting' => 'system:trusted_proxies',
			'old' => [],
			'new' => ['10.0.0.1'],
			AdminAlerts::FACT_ALERT_KEY => $alertKey,
			AdminAlerts::FACT_ALL_ADMINS => true,
		]]);
		$detection->setActionList([]);
		$detection->setCreatedTime(time());
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
