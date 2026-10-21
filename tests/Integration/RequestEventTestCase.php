<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCP\Constants;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Notification\IManager as INotificationManager;
use OCP\Notification\INotification;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Security\IHasher;
use OCP\Security\ISecureRandom;
use OCP\Server;
use OCP\Share\IManager as IShareManager;
use OCP\Share\IShare;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * Lets core code dispatch its real events to listeners of the app that see
 * a client address the test chooses.
 *
 * The listeners the app registers itself also receive these events, but on
 * the command line the request has no address, so they return at once.
 */
abstract class RequestEventTestCase extends IntegrationTestCase {
	protected Settings $settings;
	protected DetectionMapper $detections;
	/** @var IRequest&MockObject */
	protected IRequest $request;
	protected RemoteAddressResolver $addresses;
	protected string $remoteAddress = '198.51.100.7';
	/** @var list<array{class-string, callable}> */
	private array $listeners = [];
	/** @var list<string> */
	private array $createdUsers = [];
	/** @var list<int> */
	private array $shareIds = [];

	protected function setUp(): void {
		parent::setUp();
		$this->settings = Server::get(Settings::class);
		$this->detections = Server::get(DetectionMapper::class);
		$this->request = $this->createMock(IRequest::class);
		$this->request->method('getRemoteAddress')->willReturnCallback(fn (): string => $this->remoteAddress);
		$this->request->method('getHeader')->willReturnCallback(static fn (string $name): string => $name === 'User-Agent' ? 'curl/8.0' : '');
		$this->addresses = new RemoteAddressResolver($this->request, Server::get(IThrottler::class));
		Server::get(INotificationManager::class)->registerApp(CapturingNotificationApp::class);
		CapturingNotificationApp::$notifications = [];
	}

	protected function tearDown(): void {
		$dispatcher = Server::get(IEventDispatcher::class);
		foreach ($this->listeners as [$event, $listener]) {
			$dispatcher->removeListener($event, $listener);
		}
		foreach ($this->shareIds as $id) {
			$qb = $this->db->getQueryBuilder();
			$qb->delete('share')->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)))->executeStatement();
		}
		foreach ($this->createdUsers as $uid) {
			Server::get(IUserManager::class)->get($uid)?->delete();
		}
		parent::tearDown();
	}

	/**
	 * @param class-string $event
	 */
	protected function listen(string $event, IEventListener $listener): void {
		$callable = [$listener, 'handle'];
		Server::get(IEventDispatcher::class)->addListener($event, $callable);
		$this->listeners[] = [$event, $callable];
	}

	protected function user(string $prefix, ?string $email = null): IUser {
		$uid = $prefix . '-' . bin2hex(random_bytes(4));
		$user = Server::get(IUserManager::class)->createUser($uid, 'A-long-test-password-' . $uid);
		$this->assertInstanceOf(IUser::class, $user);
		$this->createdUsers[] = $uid;
		if ($email !== null) {
			$user->setSystemEMailAddress($email);
		}
		return $user;
	}

	/**
	 * A password-protected public link the user created (of a file of
	 * `$fileOwner`, if given), stored the way the
	 * sharing API stores it. The shared file is not created: the tests must
	 * not depend on setting up a user's filesystem.
	 */
	protected function linkShare(IUser $owner, string $password, string $fileName = 'Quarterly report.txt', ?IUser $fileOwner = null): IShare {
		$qb = $this->db->getQueryBuilder();
		$qb->insert('share')->values([
			'share_type' => $qb->createNamedParameter(IShare::TYPE_LINK, IQueryBuilder::PARAM_INT),
			'uid_owner' => $qb->createNamedParameter(($fileOwner ?? $owner)->getUID()),
			'uid_initiator' => $qb->createNamedParameter($owner->getUID()),
			'item_type' => $qb->createNamedParameter('file'),
			'item_source' => $qb->createNamedParameter('424242'),
			'file_source' => $qb->createNamedParameter(424242, IQueryBuilder::PARAM_INT),
			'file_target' => $qb->createNamedParameter('/' . $fileName),
			'permissions' => $qb->createNamedParameter(Constants::PERMISSION_READ, IQueryBuilder::PARAM_INT),
			'stime' => $qb->createNamedParameter(time(), IQueryBuilder::PARAM_INT),
			'token' => $qb->createNamedParameter(Server::get(ISecureRandom::class)->generate(15, ISecureRandom::CHAR_HUMAN_READABLE)),
			'password' => $qb->createNamedParameter(Server::get(IHasher::class)->hash($password)),
		])->executeStatement();
		$id = $qb->getLastInsertId();
		$this->shareIds[] = $id;
		return Server::get(IShareManager::class)->getShareById('ocinternal:' . $id);
	}

	/**
	 * @return list<Detection>
	 */
	protected function detectionsOf(string $checkId): array {
		return $this->detections->findList(new DetectionFilter(checkIds: [$checkId], limit: 1000));
	}

	/**
	 * The notifications that reached users, each once.
	 *
	 * @return list<INotification>
	 */
	protected function notifications(?string $subject = null): array {
		$unique = [];
		foreach (CapturingNotificationApp::$notifications as $notification) {
			if ($subject === null || $notification->getSubject() === $subject) {
				$unique[spl_object_id($notification)] = $notification;
			}
		}
		return array_values($unique);
	}

	protected function rows(string $table): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*'))->from($table);
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}
}
