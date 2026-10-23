<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Controller\NoticeController;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\Notification\LoginNotices;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Personal\PersonalActivity;
use OCA\IntrusionDetection\Personal\PersonalOverview;
use OCA\IntrusionDetection\WasThisYou\PersonalDetections;
use OCA\IntrusionDetection\WasThisYou\WasThisYouService;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Notification\AlreadyProcessedException;
use OCP\Notification\IManager as INotificationManager;
use OCP\Server;
use OCP\User\Events\UserCreatedEvent;
use PHPUnit\Framework\Attributes\Group;

/**
 * What the owner of an account an administrator created sees of the admin
 * change check: nothing about the creation, and a calm line of their own
 * when their administration rights change. Never the words of an attack.
 */
#[Group('DB')]
class AdminMadeAccountTest extends AdminChangeTestCase {
	private const ALARM = 'Unusual activity';

	private ?string $created = null;

	protected function tearDown(): void {
		if ($this->created !== null) {
			Server::get(IUserManager::class)->get($this->created)?->delete();
		}
		parent::tearDown();
	}

	public function testAnAccountAnAdminCreatedStartsWithoutASecurityEvent(): void {
		$user = $this->createAsAdmin();
		$this->assertSame([AdminChange::KIND_USER_CREATED], $this->kindsAbout($user), 'The administrators are told');

		$this->assertSame([], $this->eventsShownTo($user), 'Its creation is no security event for the new account');
		$overview = Server::get(PersonalOverview::class)->get($user, $this->l());
		$this->assertSame('No unusual activity in the last 30 days', $overview['status']['headline']);
		$this->assertNoAlarm($user);

		[$created] = $this->adminChanges();
		$this->assertNull(Server::get(UserAlerts::class)->notify($created), 'Never sent to the user');
		$bell = Server::get(INotificationManager::class)->createNotification();
		$bell->setApp(Application::APP_ID)
			->setUser($user->getUID())
			->setDateTime(new \DateTime())
			->setObject(UserAlerts::OBJECT_TYPE, (string)$created->getId())
			->setSubject(UserAlerts::SUBJECT, ['detection' => $created->getId()]);
		$this->expectException(AlreadyProcessedException::class);
		Server::get(Notifier::class)->prepare($bell, 'en');
	}

	public function testANewAdministratorIsToldCalmly(): void {
		$user = $this->createAsAdmin();
		$this->addAsWeb('admin', $user->getUID());
		$this->assertSame([AdminChange::KIND_USER_CREATED, AdminChange::KIND_ADMIN_GRANTED], $this->kindsAbout($user));

		$this->assertSame(['You were made an administrator'], $this->eventsShownTo($user));
		[$event] = Server::get(PersonalDetections::class)->forUser($user);
		$this->assertSame(['An administrator made you an administrator. You can now manage all accounts and settings.'], $event['happened']);
		$this->assertSame(['If you did not expect this, ask your administrators about it.'], $event['advice']);
		$this->assertFalse($event['asks'], 'Nothing to answer');
		$this->assertStringContainsString('You were made an administrator', $this->noticePage($user));
		$this->assertNoAlarm($user);
	}

	public function testAGroupAdministratorIsToldWhichGroup(): void {
		$user = $this->createAsAdmin();
		$this->createGroup('ids-ac-team');
		$this->dispatch(new \OCP\Group\Events\SubAdminAddedEvent($this->group('ids-ac-team'), $user));
		$this->assertSame(['You were made a group administrator'], $this->eventsShownTo($user));
		[$event] = Server::get(PersonalDetections::class)->forUser($user);
		$this->assertSame(['An administrator made you a group administrator of "ids-ac-team". You can now manage the accounts of that group.'], $event['happened']);
		$this->assertNoAlarm($user);
	}

	/**
	 * As the account page does: the account is created, core fires its
	 * events, and an administrator sets the email address.
	 */
	private function createAsAdmin(): IUser {
		$this->act($this->alice);
		$uid = 'ids-ac-new-' . bin2hex(random_bytes(3));
		$user = Server::get(IUserManager::class)->createUser($uid, self::PASSWORD);
		$this->assertInstanceOf(IUser::class, $user);
		$this->created = $uid;
		// Core's event, as the listener sees it in the administrator's request.
		$this->dispatch(new UserCreatedEvent($user, self::PASSWORD));
		$user->setSystemEMailAddress('new@example.com');
		return $user;
	}

	/**
	 * @return list<string>
	 */
	private function kindsAbout(IUser $user): array {
		$kinds = [];
		foreach ($this->adminChanges() as $detection) {
			if ($detection->getUid() === $user->getUID()) {
				$kinds[] = $this->facts($detection)['kind'];
			}
		}
		return $kinds;
	}

	/**
	 * The subjects of the security events on the user's security page.
	 *
	 * @return list<string>
	 */
	private function eventsShownTo(IUser $user): array {
		$activity = Server::get(PersonalActivity::class)->forUser($user, $this->l(), 30, 100);
		$subjects = array_column(array_merge($activity['questions'], array_values(array_filter(array_column($activity['items'], 'event')))), 'subject');
		$this->assertSame($subjects, array_column(Server::get(PersonalDetections::class)->forUser($user), 'subject'), 'The activity and the list of events agree');
		return $subjects;
	}

	/**
	 * Nothing the user sees calls the change an attack: the security page,
	 * its overview, the login notice and their notifications.
	 */
	private function assertNoAlarm(IUser $user): void {
		$texts = [
			'activity' => json_encode(Server::get(PersonalActivity::class)->forUser($user, $this->l(), 30, 100), JSON_THROW_ON_ERROR),
			'events' => json_encode(Server::get(PersonalDetections::class)->forUser($user), JSON_THROW_ON_ERROR),
			'overview' => json_encode(Server::get(PersonalOverview::class)->get($user, $this->l()), JSON_THROW_ON_ERROR),
			'login notice' => $this->noticePage($user),
		];
		foreach (CapturingNotificationApp::$notifications as $i => $notification) {
			if ($notification->getUser() !== $user->getUID()) {
				continue;
			}
			try {
				$prepared = Server::get(Notifier::class)->prepare(clone $notification, 'en');
			} catch (AlreadyProcessedException) {
				continue;
			}
			$texts['notification ' . $i] = $prepared->getParsedSubject() . ' ' . $prepared->getParsedMessage();
		}
		foreach ($texts as $where => $text) {
			$this->assertStringNotContainsString(self::ALARM, $text, 'In the ' . $where);
		}
	}

	private function noticePage(IUser $user): string {
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturn($user);
		$notices = $this->createMock(LoginNotices::class);
		$notices->method('shownSince')->willReturn(1);
		$page = (new NoticeController(
			Server::get(IRequest::class),
			$session,
			$notices,
			Server::get(PersonalDetections::class),
			Server::get(WasThisYouService::class),
			Server::get(IURLGenerator::class),
			Server::get(LocalRedirect::class),
			$this->l(),
		))->show();
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $page);
		return $page->render();
	}

	private function l(): IL10N {
		return Server::get(IFactory::class)->get(Application::APP_ID, 'en');
	}
}
