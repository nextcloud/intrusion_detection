<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\BackgroundJob\LearningModeJob;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Controller\LearningActionController;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Notification\AdminRecipients;
use OCA\IntrusionDetection\Notification\LearningNotices;
use OCA\IntrusionDetection\Notification\Notifier;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IGroupManager;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Notification\IManager as INotificationManager;
use OCP\Notification\INotification;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\MockObject;

#[Group('DB')]
class LearningNoticesTest extends IntegrationTestCase {
	/** @var INotificationManager&MockObject */
	private INotificationManager $notifications;
	/** @var list<INotification> */
	private array $sent = [];
	private int $dismissed = 0;
	private LearningNotices $notices;
	private LearningService $learning;
	private Settings $settings;
	private string $groupId;
	/** @var list<IUser> */
	private array $users = [];

	protected function setUp(): void {
		parent::setUp();
		$real = Server::get(INotificationManager::class);
		$this->notifications = $this->createMock(INotificationManager::class);
		$this->notifications->method('createNotification')->willReturnCallback(static fn (): INotification => $real->createNotification());
		$this->notifications->method('notify')->willReturnCallback(function (INotification $n): void {
			$this->sent[] = $n;
		});
		$this->notifications->method('markProcessed')->willReturnCallback(function (INotification $n): void {
			$this->assertSame(LearningNotices::OBJECT_TYPE, $n->getObjectType());
			$this->dismissed++;
		});
		$this->settings = Server::get(Settings::class);
		$this->learning = Server::get(LearningService::class);

		// The administrators are the members of the configured groups, enabled ones only.
		$this->groupId = 'ids-admins-' . bin2hex(random_bytes(3));
		$group = Server::get(IGroupManager::class)->createGroup($this->groupId);
		foreach (['one', 'two', 'off'] as $name) {
			$user = Server::get(IUserManager::class)->createUser($this->groupId . '-' . $name, 'A-long-test-password-1');
			$group->addUser($user);
			$this->users[] = $user;
		}
		$this->users[2]->setEnabled(false);
		$this->settings->setGlobal(GlobalSettings::NOTIFY_ADMIN_GROUP, [$this->groupId]);

		$this->notices = new LearningNotices(
			$this->settings,
			$this->learning,
			Server::get(AdminRecipients::class),
			$this->notifications,
			Server::get(DetectionMapper::class),
			Server::get(IURLGenerator::class),
			Server::get(ITimeFactory::class),
		);
	}

	protected function tearDown(): void {
		foreach ($this->users as $user) {
			$user->delete();
		}
		Server::get(IGroupManager::class)->get($this->groupId)?->delete();
		parent::tearDown();
	}

	public function testTheNoticeIsSentOnceADayBeforeTheEnd(): void {
		$this->learning->start(7, 'test');
		$this->assertFalse($this->notices->sendEndingNoticeIfDue(), 'Too early');

		$this->setLearningUntil(time() + 3600);
		$this->assertTrue($this->notices->sendEndingNoticeIfDue());
		$this->assertFalse($this->notices->sendEndingNoticeIfDue(), 'Only once per learning period');
		$this->assertCount(2, $this->sent, 'Disabled members are not notified');

		$notification = $this->sent[0];
		$this->assertSame(Notifier::SUBJECT_LEARNING_ENDS, $notification->getSubject());
		$links = array_map(static fn ($a): string => $a->getLink(), $notification->getActions());
		$this->assertStringContainsString('/ocs/v2.php/apps/intrusion_detection/api/v1/learning/protect', $links[0]);
		$this->assertStringContainsString('/ocs/v2.php/apps/intrusion_detection/api/v1/learning/extend', $links[1]);
		$this->assertSame(['POST', 'POST'], array_map(static fn ($a): string => $a->getRequestType(), $notification->getActions()));

		$prepared = Server::get(Notifier::class)->prepare($notification, 'en');
		$this->assertSame('The learning period of intrusion detection ends tomorrow', $prepared->getParsedSubject());
		$this->assertSame(['Start protecting now', 'Observe 7 more days'], array_map(static fn ($a): string => $a->getParsedLabel(), $prepared->getParsedActions()));
	}

	public function testStartProtectingNowEndsLearningOnceAndIsIdempotent(): void {
		$this->setLearningUntil(time() + 3600);
		$this->notices->sendEndingNoticeIfDue();

		$this->assertTrue($this->notices->startProtecting('admin'));
		$this->assertFalse($this->learning->isActive());
		$this->assertFalse($this->notices->startProtecting('admin'), 'A second click changes nothing');
		$this->assertGreaterThanOrEqual(1, $this->dismissed);
	}

	public function testObserveLongerExtendsBySevenDaysOnlyOnce(): void {
		$until = time() + 3600;
		$this->setLearningUntil($until);
		$this->notices->sendEndingNoticeIfDue();

		$this->assertTrue($this->notices->observeLonger('admin'));
		$this->assertSame($until + 7 * 86400, $this->learning->until());
		$this->assertFalse($this->notices->observeLonger('admin'), 'The notice is answered');
		$this->assertSame($until + 7 * 86400, $this->learning->until());
	}

	public function testAStaleNoticeDoesNotEndARestartedLearningPeriod(): void {
		$this->setLearningUntil(time() + 3600);
		$this->notices->sendEndingNoticeIfDue();
		$this->learning->start(14, 'another admin');
		$this->assertFalse($this->notices->startProtecting('admin'));
		$this->assertTrue($this->learning->isActive());
	}

	public function testTheJobTellsTheAdminsWhenProtectionStarts(): void {
		$this->setLearningUntil(time() - 10);
		$job = new LearningModeJob(Server::get(ITimeFactory::class), $this->learning, $this->notices);
		self::invokePrivate($job, 'run', [null]);
		$this->assertFalse($this->learning->isActive());
		$this->assertSame([Notifier::SUBJECT_PROTECTION_STARTED, Notifier::SUBJECT_PROTECTION_STARTED], array_map(static fn (INotification $n): string => $n->getSubject(), $this->sent));
		$this->assertSame('Intrusion detection is now protecting this server', Server::get(Notifier::class)->prepare($this->sent[0], 'en')->getParsedSubject());
	}

	public function testTheActionEndpointsUseTheNotices(): void {
		$this->setLearningUntil(time() + 3600);
		$this->notices->sendEndingNoticeIfDue();
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturn($this->users[0]);
		$controller = new LearningActionController($this->createMock(IRequest::class), $this->notices, $this->learning, $session);

		$data = $controller->extend()->getData();
		$this->assertSame(['changed' => true, 'learning' => true, 'until' => $this->learning->until()], $data);
		$this->assertFalse($controller->protect()->getData()['changed']);
	}

	private function setLearningUntil(int $until): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, $until);
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_NOTICE_SENT, 0);
	}
}
