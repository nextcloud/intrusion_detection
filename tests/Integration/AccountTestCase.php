<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Authentication\Token\IProvider as PrivateTokenProvider;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Event\TypedEvents;
use OCA\IntrusionDetection\Notification\AdminNotices;
use OCA\IntrusionDetection\Notification\LoginNotices;
use OCA\IntrusionDetection\Notification\MailContent;
use OCA\IntrusionDetection\Notification\MailQueue;
use OCA\IntrusionDetection\Notification\Mails;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Response\Handlers\KillSessionHandler;
use OCA\IntrusionDetection\Response\Handlers\NotifyUserHandler;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\SessionKiller;
use OCA\IntrusionDetection\Response\Tokens;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\WasThisYou\Questions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Exceptions\InvalidTokenException;
use OCP\Authentication\Token\IProvider;
use OCP\Authentication\Token\IToken;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Notification\IManager as INotificationManager;
use OCP\Notification\INotification;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * Real accounts, real session tokens and app passwords from core's token
 * provider, and a session whose id is one of those tokens. Notifications
 * are captured; emails are captured instead of sent.
 */
abstract class AccountTestCase extends IntegrationTestCase {
	protected Settings $settings;
	protected PrivateTokenProvider $tokens;
	protected TestSession $session;
	protected CurrentSession $currentSession;
	/** @var IUserSession&MockObject */
	protected IUserSession $userSession;
	/** @var Mails&MockObject */
	protected Mails $mails;
	/** @var list<array{string, MailContent}> */
	protected array $mailed = [];
	protected bool $mailWorks = true;
	protected ?IUser $sessionUser = null;
	/** @var list<string> */
	private array $createdUsers = [];

	protected function setUp(): void {
		parent::setUp();
		$this->settings = Server::get(Settings::class);
		$this->tokens = Server::get(PrivateTokenProvider::class);
		$this->session = new TestSession();
		$this->currentSession = new CurrentSession($this->session, Server::get(IProvider::class), Server::get(LoggerInterface::class));
		$this->userSession = $this->createMock(IUserSession::class);
		$this->userSession->method('getUser')->willReturnCallback(fn (): ?IUser => $this->sessionUser);
		$this->userSession->method('isLoggedIn')->willReturnCallback(fn (): bool => $this->sessionUser !== null);
		$this->mails = $this->createMock(Mails::class);
		$this->mails->method('send')->willReturnCallback(function (IUser $user, MailContent $content): bool {
			if ((string)$user->getEMailAddress() === '' || !$this->mailWorks) {
				return false;
			}
			$this->mailed[] = [$user->getUID(), $content];
			return true;
		});
		Server::get(INotificationManager::class)->registerApp(CapturingNotificationApp::class);
		CapturingNotificationApp::$notifications = [];
	}

	protected function tearDown(): void {
		foreach ($this->createdUsers as $uid) {
			Server::get(IUserManager::class)->get($uid)?->delete();
		}
		parent::tearDown();
	}

	protected function newUser(string $prefix, ?string $email = null): IUser {
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
	 * A real token of core's provider.
	 *
	 * @return array{id: int, secret: string}
	 */
	protected function token(IUser $user, int $type, string $name): array {
		$secret = bin2hex(random_bytes(36));
		$token = $this->tokens->generateToken($secret, $user->getUID(), $user->getUID(), 'A-long-test-password-' . $user->getUID(), $name, $type);
		return ['id' => $token->getId(), 'secret' => $secret];
	}

	/**
	 * Log the test session in with a new browser session token of the account.
	 *
	 * @return array{id: int, secret: string}
	 */
	protected function startSession(IUser $user, string $name = 'Firefox on Linux'): array {
		$token = $this->token($user, IToken::TEMPORARY_TOKEN, $name);
		$this->session->id = $token['secret'];
		$this->sessionUser = $user;
		return $token;
	}

	protected function tokenExists(int $id): bool {
		try {
			$this->tokens->getTokenById($id);
			return true;
		} catch (InvalidTokenException) {
			return false;
		}
	}

	protected function userAlerts(): UserAlerts {
		return new UserAlerts(
			Server::get(AlertMapper::class),
			Server::get(INotificationManager::class),
			$this->mails,
			Server::get(UserMessages::class),
			Server::get(AdminNotices::class),
			Server::get(IUserManager::class),
			Server::get(ITimeFactory::class),
			Server::get(LoginNotices::class),
			Server::get(Questions::class),
			Server::get(MailQueue::class),
			Server::get(CheckRegistry::class),
		);
	}

	/**
	 * Run the queued alert emails, the users' through the captured mails.
	 *
	 * @return int how many ran
	 */
	protected function sendQueuedMails(): int {
		return $this->runQueuedMails($this->userAlerts());
	}

	protected function sessionKiller(): SessionKiller {
		return new SessionKiller(
			Server::get(Tokens::class),
			Server::get(TokenOriginMapper::class),
			$this->currentSession,
			$this->userSession,
			Server::get(ITimeFactory::class),
			Server::get(AuditLogger::class),
		);
	}

	/**
	 * The response engine, with the test session and the captured emails.
	 */
	protected function engine(): ResponseEngine {
		return new ResponseEngine(
			Server::get(CheckRegistry::class),
			$this->settings,
			Server::get(DetectionService::class),
			new OverridingContainer([
				KillSessionHandler::class => new KillSessionHandler($this->sessionKiller()),
				NotifyUserHandler::class => new NotifyUserHandler($this->userAlerts()),
			]),
			Server::get(TypedEvents::class),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
		);
	}

	/**
	 * The notifications sent to one account. The capturing app may be
	 * registered more than once in a test run, so each is listed once.
	 *
	 * @return list<INotification>
	 */
	protected function notificationsFor(string $uid, ?string $subject = null): array {
		$found = [];
		foreach (CapturingNotificationApp::$notifications as $n) {
			if ($n->getUser() === $uid && ($subject === null || $n->getSubject() === $subject)) {
				$found[spl_object_id($n)] = $n;
			}
		}
		return array_values($found);
	}
}
