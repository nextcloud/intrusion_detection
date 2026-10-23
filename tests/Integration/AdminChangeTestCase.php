<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Group\Database as DatabaseGroupBackend;
use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\AdminGrantGate;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AdminChange\ConfigWatch;
use OCA\IntrusionDetection\AdminChange\Db\ConfigSnapshotMapper;
use OCA\IntrusionDetection\AdminChange\DelegatedGroups;
use OCA\IntrusionDetection\AdminChange\GrantPermit;
use OCA\IntrusionDetection\AdminChange\WatchedSettings;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChangeDetector;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Listener\AdminChangeListener;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Signal\SignalDispatcher;
use OCA\IntrusionDetection\State\AppState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\Event;
use OCP\IAppConfig;
use OCP\IGroup;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Notification\IManager as INotificationManager;
use OCP\Notification\INotification;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * Real accounts, groups and database for the admin change check, with the
 * actor under the test's control.
 *
 * The app's own listener is registered in this process as well and sees
 * every real group change with the actor "cron" (tests run on the command
 * line). Changes that a test attributes to someone are therefore made in the
 * group backend directly and handed to a listener built here, with a mocked
 * {@see ActorResolver}.
 */
abstract class AdminChangeTestCase extends IntegrationTestCase {
	protected const PASSWORD = 'Ids-Test-Password-7f3a';

	protected string $alice;
	protected string $carol;
	protected string $bob;
	protected string $dave;

	protected string $actor = 'unknown';
	protected bool $commandLine = false;
	protected bool $console = false;

	/** @var ActorResolver&MockObject */
	protected ActorResolver $actors;
	protected SignalDispatcher $signals;
	protected AdminGrantGate $gate;
	protected AdminChangeListener $listener;
	protected DetectionMapper $detections;

	/** @var array<class-string, array{alice: string, carol: string, bob: string, dave: string}> accounts per test class, created once */
	private static array $accounts = [];
	/** @var list<string> */
	private array $createdGroups = [];
	private static bool $capturing = false;

	protected function setUp(): void {
		parent::setUp();
		if (!self::$capturing) {
			// Registered apps stay for the whole process; once is enough.
			Server::get(INotificationManager::class)->registerApp(CapturingNotificationApp::class);
			self::$capturing = true;
		}
		CapturingNotificationApp::$notifications = [];

		if (!isset(self::$accounts[static::class])) {
			// Created once per class: hashing their passwords is the slow part.
			$suffix = bin2hex(random_bytes(3));
			self::$accounts[static::class] = [
				'alice' => self::createAccount('ids-ac-alice-' . $suffix, 'alice@example.com'),
				'carol' => self::createAccount('ids-ac-carol-' . $suffix, null),
				'bob' => self::createAccount('ids-ac-bob-' . $suffix, null),
				'dave' => self::createAccount('ids-ac-dave-' . $suffix, null),
			];
		}
		['alice' => $this->alice, 'carol' => $this->carol, 'bob' => $this->bob, 'dave' => $this->dave] = self::$accounts[static::class];
		$admins = $this->group('admin');
		foreach ([$this->alice, $this->carol] as $uid) {
			$admins->addUser($this->user($uid));
		}
		foreach ([$this->bob, $this->dave] as $uid) {
			$admins->removeUser($this->user($uid));
		}

		// Accounts and groups exist; from here on the check runs.
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode(AdminChange::ID), Mode::Protect->value);

		$this->actors = $this->createMock(ActorResolver::class);
		$this->actors->method('actor')->willReturnCallback(fn (): string => $this->actor);
		$this->actors->method('isCommandLine')->willReturnCallback(fn (): bool => $this->commandLine);
		$this->actors->method('isConsole')->willReturnCallback(fn (): bool => $this->console);
		$this->detections = Server::get(DetectionMapper::class);
		$this->rebuild();
	}

	protected function tearDown(): void {
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode(AdminChange::ID), Mode::Off->value);
		$groupManager = Server::get(IGroupManager::class);
		foreach ($this->createdGroups as $gid) {
			$groupManager->get($gid)?->delete();
		}
		$qb = $this->db->getQueryBuilder();
		$qb->delete('authorized_groups')->where($qb->expr()->like('group_id', $qb->createNamedParameter('ids-ac-%')))->executeStatement();
		parent::tearDown();
	}

	/**
	 * Build the listener and its helpers again, e.g. after changing delegations.
	 */
	protected function rebuild(?ITimeFactory $time = null): void {
		$time ??= Server::get(ITimeFactory::class);
		$this->signals = $this->dispatcher([AdminChangeDetector::class => new AdminChangeDetector($this->actors, Server::get(RemoteAddressResolver::class))]);
		$this->gate = new AdminGrantGate($this->appSettings(), $this->checkSettings(), $this->actors, Server::get(GrantPermit::class));
		$this->listener = new AdminChangeListener(
			$this->signals,
			$this->gate,
			Server::get(ApprovalService::class),
			Server::get(GrantPermit::class),
			new DelegatedGroups(Server::get(\OC\Settings\AuthorizedGroupMapper::class), Server::get(LoggerInterface::class)),
			$this->configWatch(Server::get(WatchedSettings::class), $time),
			$this->actors,
			Server::get(RemoteAddressResolver::class),
			Server::get(IGroupManager::class),
			Server::get(LoggerInterface::class),
		);
	}

	protected function configWatch(WatchedSettings $watched, ?ITimeFactory $time = null, ?\OCP\App\IAppManager $appManager = null): ConfigWatch {
		return new ConfigWatch($watched, Server::get(ConfigSnapshotMapper::class), Server::get(Fingerprinter::class), $this->signals, $this->checkSettings(), $time ?? Server::get(ITimeFactory::class), $appManager ?? Server::get(\OCP\App\IAppManager::class), Server::get(AppState::class));
	}

	protected function requireApproval(bool $on = true): void {
		$this->appConfig->setValueBool(Application::APP_ID, GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL, $on);
	}

	protected function act(string $actor, bool $commandLine = false, bool $console = false): void {
		$this->actor = $actor;
		$this->commandLine = $commandLine;
		$this->console = $console;
	}

	protected function dispatch(Event $event): void {
		$this->listener->handle($event);
	}

	/**
	 * Add an account to a group the way the web interface does, as seen by
	 * the listener under test: the membership is written, then the event.
	 */
	protected function addAsWeb(string $gid, string $uid): void {
		$this->databaseBackend()->addToGroup($uid, $gid);
		$this->dispatch(new \OCP\Group\Events\UserAddedEvent($this->group($gid), $this->user($uid)));
	}

	protected function createGroup(string $gid): IGroup {
		$group = Server::get(IGroupManager::class)->createGroup($gid);
		$this->assertNotNull($group);
		$this->createdGroups[] = $gid;
		return $group;
	}

	protected function group(string $gid): IGroup {
		$group = Server::get(IGroupManager::class)->get($gid);
		$this->assertNotNull($group);
		return $group;
	}

	protected function user(string $uid): IUser {
		$user = Server::get(IUserManager::class)->get($uid);
		$this->assertNotNull($user);
		return $user;
	}

	protected function inGroup(string $gid, string $uid): bool {
		return $this->databaseBackend()->inGroup($uid, $gid);
	}

	/**
	 * @return list<Detection> of this check, oldest first
	 */
	protected function adminChanges(): array {
		return array_reverse($this->detections->findList(new DetectionFilter(checkIds: [AdminChange::ID], limit: 100)));
	}

	/**
	 * @return array<string, mixed>
	 */
	protected function facts(Detection $detection): array {
		return $detection->getExplanationData()['facts'] ?? [];
	}

	/**
	 * @return list<INotification>
	 */
	protected function notificationsWithSubject(string $subject): array {
		// The capturing app may be registered more than once in this process; each copy sees the same object.
		$unique = [];
		foreach (CapturingNotificationApp::$notifications as $notification) {
			if ($notification->getSubject() === $subject) {
				$unique[spl_object_id($notification)] = $notification;
			}
		}
		return array_values($unique);
	}

	public static function tearDownAfterClass(): void {
		Server::get(IAppConfig::class)->setValueString(Application::APP_ID, Keys::mode(AdminChange::ID), Mode::Off->value);
		foreach (self::$accounts[static::class] ?? [] as $uid) {
			Server::get(IUserManager::class)->get($uid)?->delete();
		}
		unset(self::$accounts[static::class]);
		Server::get(IAppConfig::class)->deleteKey(Application::APP_ID, Keys::mode(AdminChange::ID));
		parent::tearDownAfterClass();
	}

	private static function createAccount(string $uid, ?string $email): string {
		$user = Server::get(IUserManager::class)->createUser($uid, self::PASSWORD);
		if (!$user instanceof IUser) {
			throw new \RuntimeException('Could not create ' . $uid);
		}
		if ($email !== null) {
			$user->setSystemEMailAddress($email);
		}
		return $uid;
	}

	private function databaseBackend(): DatabaseGroupBackend {
		foreach (Server::get(IGroupManager::class)->getBackends() as $backend) {
			if ($backend instanceof DatabaseGroupBackend) {
				return $backend;
			}
		}
		$this->fail('No database group backend');
	}
}
