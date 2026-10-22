<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\BackgroundJob\LearningModeJob;
use OCA\IntrusionDetection\Check\Checks\ManualBlock;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\Notification\AdminRecipients;
use OCA\IntrusionDetection\Notification\LearningNotices;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Notification\AlreadyProcessedException;
use OCP\Notification\IManager as INotificationManager;
use OCP\Notification\INotification;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
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
		$this->learning = new LearningService($this->settings, Server::get(ITimeFactory::class), Server::get(AuditLogger::class), $this->notifications);

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
			Server::get(AdminLinks::class),
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
		$this->assertStringContainsString('/settings/admin/intrusion_detection', $links[0], 'Both need the password, which the notification cannot ask');
		$this->assertStringContainsString('/settings/admin/intrusion_detection', $links[1]);
		$this->assertSame(['WEB', 'WEB'], array_map(static fn ($a): string => $a->getRequestType(), $notification->getActions()));

		$prepared = Server::get(Notifier::class)->prepare($notification, 'en');
		$this->assertSame('The learning period of intrusion detection ends tomorrow', $prepared->getParsedSubject());
		$this->assertSame(['Start protecting now', 'Observe 7 more days'], array_map(static fn ($a): string => $a->getParsedLabel(), $prepared->getParsedActions()));
		$this->assertSame(['WEB', 'WEB'], array_map(static fn ($a): string => $a->getRequestType(), $prepared->getParsedActions()), 'Also for notices sent with the old POST links');
	}

	/**
	 * @return array<string, array{\Closure(LearningService): mixed}>
	 */
	public static function periodChanges(): array {
		return [
			'start' => [static fn (LearningService $learning) => $learning->start(14, 'admin')],
			'extend' => [static fn (LearningService $learning) => $learning->extend(7, 'admin')],
			'end' => [static fn (LearningService $learning) => $learning->stop('admin')],
		];
	}

	/**
	 * @param \Closure(LearningService): mixed $change
	 */
	#[DataProvider('periodChanges')]
	public function testChangingThePeriodRemovesTheNotice(\Closure $change): void {
		$this->setLearningUntil(time() + 3600);
		$this->notices->sendEndingNoticeIfDue();
		$notice = $this->sent[0];
		$this->assertSame('The learning period of intrusion detection ends tomorrow', Server::get(Notifier::class)->prepare($notice, 'en')->getParsedSubject());

		$change($this->learning);
		$this->assertSame(1, $this->dismissed);
		$this->expectException(AlreadyProcessedException::class);
		Server::get(Notifier::class)->prepare($notice, 'en');
	}

	public function testExtendingSendsTheNoticeAgainBeforeTheNewEnd(): void {
		$this->setLearningUntil(time() + 3600);
		$this->assertTrue($this->notices->sendEndingNoticeIfDue());
		$this->learning->extend(3, 'admin');
		$this->assertFalse($this->notices->sendEndingNoticeIfDue(), 'Not before the last day of the new period');

		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 3600);
		$this->assertTrue($this->notices->sendEndingNoticeIfDue(), 'The last day of the new period has its notice');
	}

	public function testTheNoticeIsGoneOnceLearningEndedByItself(): void {
		$this->setLearningUntil(time() + 3600);
		$this->notices->sendEndingNoticeIfDue();
		$notice = $this->sent[0];
		$this->setLearningUntil(time() - 10);
		$this->assertTrue($this->learning->expireIfDue());
		$this->assertSame(1, $this->dismissed);
		$this->expectException(AlreadyProcessedException::class);
		Server::get(Notifier::class)->prepare($notice, 'en');
	}

	public function testTheNoticeSaysWhatStillBlocksWhileLearning(): void {
		$this->setLearningUntil(time() + 3600);
		$this->notices->sendEndingNoticeIfDue();
		$message = Server::get(Notifier::class)->prepare($this->sent[0], 'en')->getParsedMessage();
		$this->assertStringContainsString('earlier blocks, blocks you add by hand, a user\'s "No, it was not me", decoys and reserved names still block.', $message);
		$this->assertStringNotContainsString('blocks nothing', $message);
	}

	public function testTheJobTellsTheAdminsWhenProtectionStarts(): void {
		$this->setLearningUntil(time() - 10);
		$job = new LearningModeJob(Server::get(ITimeFactory::class), $this->learning, $this->notices);
		self::invokePrivate($job, 'run', [null]);
		$this->assertFalse($this->learning->isActive());
		$this->assertSame(1, $this->dismissed, 'The notice about the ending period goes');
		$this->assertSame([Notifier::SUBJECT_PROTECTION_STARTED, Notifier::SUBJECT_PROTECTION_STARTED], array_map(static fn (INotification $n): string => $n->getSubject(), $this->sent));
		$this->assertSame('Intrusion detection is now protecting this server', Server::get(Notifier::class)->prepare($this->sent[0], 'en')->getParsedSubject());
	}

	public function testTheNoticeCountsWhatLearningHeldBackAndTheAddressesItWouldHaveBlocked(): void {
		$this->learning->start(7, 'test');
		$engine = Server::get(ResponseEngine::class);
		// Two detections from one address and one from another, all held back by learning mode.
		foreach (['198.51.100.7', '198.51.100.7', '198.51.100.8'] as $i => $ip) {
			$engine->handle(new DetectionDraft(ManualBlock::ID, SourceKey::fromIp($ip), facts: ['n' => $i]));
		}
		// A check set to Observe on purpose is not what learning held back.
		$engine->handle(new DetectionDraft(ManualBlock::ID, SourceKey::fromIp('198.51.100.9')), null, new ModeState(Mode::Observe, Mode::Observe));

		$this->setLearningUntil(time() + 3600);
		$this->assertTrue($this->notices->sendEndingNoticeIfDue());
		$params = $this->sent[0]->getSubjectParameters();
		$this->assertSame(3, $params['detections']);
		$this->assertSame(2, $params['blocks'], 'Addresses, not detections');
	}

	private function setLearningUntil(int $until): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, $until);
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_NOTICE_SENT, 0);
	}
}
