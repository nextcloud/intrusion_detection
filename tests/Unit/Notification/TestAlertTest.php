<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Notification;

use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\Notification\MailContent;
use OCA\IntrusionDetection\Notification\Mails;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Notification\TestAlert;
use OCA\IntrusionDetection\Notification\UserLinks;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\WasThisYou\Questions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Notification\IManager as INotificationManager;
use OCP\Notification\INotification;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class TestAlertTest extends TestCase {
	private INotificationManager&MockObject $notifications;
	private Mails&MockObject $mails;
	private Prerequisites&MockObject $prerequisites;
	/** @var list<INotification> */
	private array $sent = [];

	protected function setUp(): void {
		parent::setUp();
		$this->notifications = $this->createMock(INotificationManager::class);
		$this->notifications->method('createNotification')->willReturnCallback(static fn (): INotification => Server::get(INotificationManager::class)->createNotification());
		$this->notifications->method('notify')->willReturnCallback(function (INotification $n): void {
			$this->sent[] = $n;
		});
		$this->mails = $this->createMock(Mails::class);
		$this->prerequisites = $this->createMock(Prerequisites::class);
	}

	private function alert(): TestAlert {
		$links = $this->createMock(AdminLinks::class);
		$links->method('adminPage')->willReturn('https://cloud.example.com/settings/admin/intrusion_detection');
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(1_790_000_000);
		$factory = $this->createMock(IFactory::class);
		$factory->method('getUserLanguage')->willReturn('en');
		$factory->method('get')->willReturn(Server::get(IFactory::class)->get('intrusion_detection', 'en'));
		return new TestAlert($this->notifications, $this->mails, $this->prerequisites, $factory, $links, $time);
	}

	private function user(string $email): IUser&MockObject {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$user->method('getEMailAddress')->willReturn($email === '' ? null : $email);
		return $user;
	}

	public function testBellAndEmailAreMarkedAsATest(): void {
		$this->prerequisites->method('hasMail')->willReturn(true);
		$this->mails->expects($this->once())->method('send')->willReturnCallback(function (IUser $user, MailContent $content): bool {
			$this->assertStringStartsWith('[Test]', $content->subject);
			$this->assertSame('intrusion_detection.testAlert', $content->templateId);
			$this->assertStringContainsString('Nothing has happened', implode(' ', $content->paragraphs));
			$this->assertSame('https://cloud.example.com/settings/admin/intrusion_detection', $content->buttonUrl);
			return true;
		});
		$this->assertSame(['bell' => true, 'email' => 'sent', 'address' => 'alice@example.org'], $this->alert()->send($this->user('alice@example.org')));
		$this->assertCount(1, $this->sent);
		$this->assertSame('alice', $this->sent[0]->getUser());
		$this->assertSame(TestAlert::SUBJECT, $this->sent[0]->getSubject());
	}

	public function testWithoutAnAddressOrMailOnlyTheBellIsSent(): void {
		$this->mails->expects($this->never())->method('send');
		$this->prerequisites->method('hasMail')->willReturn(false);
		$this->assertSame('no_address', $this->alert()->send($this->user(''))['email']);
		$this->assertSame('no_mail', $this->alert()->send($this->user('alice@example.org'))['email']);
		$this->assertCount(2, $this->sent);
	}

	public function testAFailedEmailIsReported(): void {
		$this->prerequisites->method('hasMail')->willReturn(true);
		$this->mails->method('send')->willReturn(false);
		$this->assertSame('failed', $this->alert()->send($this->user('alice@example.org'))['email']);
	}

	public function testTheNotifierRendersTheTestAlert(): void {
		$links = $this->createMock(AdminLinks::class);
		$links->method('adminPage')->willReturn('https://cloud.example.com/settings/admin/intrusion_detection');
		$links->method('icon')->willReturn('https://cloud.example.com/icon.svg');
		$notifier = new Notifier(
			Server::get(IFactory::class),
			$this->createMock(AlertMapper::class),
			$this->createMock(DetectionMapper::class),
			$this->createMock(AdminAlerts::class),
			$this->createMock(NarrativeBuilder::class),
			$links,
			$this->createMock(UserMessages::class),
			$this->createMock(UserLinks::class),
			$this->createMock(IUserManager::class),
			$this->createMock(ApprovalMapper::class),
			$this->createMock(DateFormatter::class),
			$this->createMock(Questions::class),
			$this->createMock(IURLGenerator::class),
			$this->createMock(LearningService::class),
		);
		$notification = Server::get(INotificationManager::class)->createNotification();
		$notification->setApp('intrusion_detection')->setUser('alice')->setDateTime(new \DateTime())->setObject(TestAlert::OBJECT_TYPE, '1')->setSubject(TestAlert::SUBJECT);
		$prepared = $notifier->prepare($notification, 'en');
		$this->assertSame('Test alert from intrusion detection', $prepared->getParsedSubject());
		$this->assertStringContainsString('Nothing has happened', $prepared->getParsedMessage());
		$this->assertSame('https://cloud.example.com/settings/admin/intrusion_detection#settings-notifications', $prepared->getLink());
	}
}
