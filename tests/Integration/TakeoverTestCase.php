<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\AccountTakeover\AccountTakeoverDetector;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Event\TypedEvents;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Guide\SecureAccountGuide;
use OCA\IntrusionDetection\Listener\SecurityChangeListener;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\Notification\AdminRecipients;
use OCA\IntrusionDetection\Notification\Db\AlertMapper;
use OCA\IntrusionDetection\Notification\MailContent;
use OCA\IntrusionDetection\Notification\MailQueue;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Response\Handlers\KillSessionHandler;
use OCA\IntrusionDetection\Response\Handlers\LockLinkHandler;
use OCA\IntrusionDetection\Response\Handlers\NotifyAdminHandler;
use OCA\IntrusionDetection\Response\Handlers\NotifyUserHandler;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\Tokens;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\Takeover\AccountLock;
use OCA\IntrusionDetection\Takeover\Db\LockLinkMapper;
use OCA\IntrusionDetection\Takeover\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Takeover\LockLinks;
use OCA\IntrusionDetection\Takeover\ResetTracker;
use OCA\IntrusionDetection\Takeover\RiskyLogins;
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCA\IntrusionDetection\Takeover\Signals\UnconfirmedLoginSignal;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\Defaults;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Notification\IManager as INotificationManager;
use OCP\Security\ICrypto;
use OCP\Security\ISecureRandom;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * The security change log, the takeover check and the lock link, wired
 * with the test session, a controlled actor and captured emails.
 *
 * Core's real code paths dispatch the events. The app's own listener is
 * registered in this process too and records them as made by the system
 * (tests run on the command line), which never counts. The listener built
 * here is added to the dispatcher for the test, with the actor the test
 * chooses, so the same real events count as the test says.
 */
abstract class TakeoverTestCase extends AccountTestCase {
	protected const IP = '203.0.113.7';

	protected string $actor = 'self';
	/** @var ActorResolver&MockObject */
	protected ActorResolver $actors;
	protected SessionState $state;
	/** @var list<array{string, MailContent}> emails sent to an address that is not the account's own */
	protected array $sentTo = [];
	/** @var array<class-string<Event>, callable> */
	private array $listeners = [];

	protected function setUp(): void {
		parent::setUp();
		$this->actors = $this->createMock(ActorResolver::class);
		$this->actors->method('isConsole')->willReturnCallback(fn (): bool => $this->actor === 'occ');
		$this->actors->method('isCommandLine')->willReturnCallback(fn (): bool => in_array($this->actor, ['occ', 'cron'], true));
		$this->state = new SessionState($this->session, Server::get(LoggerInterface::class));
		$this->mails->method('sendTo')->willReturnCallback(function (string $address, string $name, MailContent $content): bool {
			$this->sentTo[] = [$address, $content];
			return true;
		});
		$listener = $this->listener();
		foreach (SecurityChangeListenerEvents::ALL as $event) {
			$callable = [$listener, 'handle'];
			$this->listeners[$event] = $callable;
			Server::get(IEventDispatcher::class)->addListener($event, $callable);
		}
	}

	protected function tearDown(): void {
		foreach ($this->listeners as $event => $callable) {
			Server::get(IEventDispatcher::class)->removeListener($event, $callable);
		}
		parent::tearDown();
	}

	protected function request(?string $ip = self::IP): IRequest {
		$request = $this->createMock(IRequest::class);
		$request->method('getRemoteAddress')->willReturn((string)$ip);
		$request->method('getHeader')->willReturnCallback(static fn (string $name): string => $name === 'User-Agent' ? 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0' : '');
		return $request;
	}

	protected function addresses(?string $ip = self::IP): RemoteAddressResolver {
		return new RemoteAddressResolver($this->request($ip), Server::get(\OCP\Security\Bruteforce\IThrottler::class), Server::get(ServerAddresses::class));
	}

	protected function lockLinks(): LockLinks {
		return new LockLinks(
			Server::get(LockLinkMapper::class),
			Server::get(SecurityChangeMapper::class),
			Server::get(Fingerprinter::class),
			Server::get(ISecureRandom::class),
			Server::get(ICrypto::class),
			$this->mails,
			Server::get(UserMessages::class),
			Server::get(DateFormatter::class),
			Server::get(IURLGenerator::class),
			Server::get(Defaults::class),
			Server::get(ITimeFactory::class),
			Server::get(LoggerInterface::class),
		);
	}

	protected function adminAlerts(): AdminAlerts {
		return new AdminAlerts(
			Server::get(AlertMapper::class),
			Server::get(AdminRecipients::class),
			Server::get(INotificationManager::class),
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

	#[\Override]
	protected function sendQueuedMails(): int {
		return $this->runQueuedMails($this->userAlerts(), $this->adminAlerts());
	}

	protected function takeoverEngine(): ResponseEngine {
		return new ResponseEngine(
			Server::get(CheckRegistry::class),
			$this->checkSettings(),
			Server::get(DetectionService::class),
			new OverridingContainer([
				KillSessionHandler::class => new KillSessionHandler($this->sessionKiller()),
				NotifyUserHandler::class => new NotifyUserHandler($this->userAlerts()),
				NotifyAdminHandler::class => new NotifyAdminHandler($this->adminAlerts()),
				LockLinkHandler::class => new LockLinkHandler($this->lockLinks(), Server::get(IUserManager::class)),
			]),
			Server::get(TypedEvents::class),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
		);
	}

	protected function detector(): AccountTakeoverDetector {
		return new AccountTakeoverDetector(
			$this->checkSettings(),
			Server::get(SecurityChangeMapper::class),
			new RiskyLogins(new OverridingContainer([UnconfirmedLoginSignal::class => new UnconfirmedLoginSignal($this->state, $this->currentSession)]), Server::get(LoggerInterface::class)),
			$this->addresses(),
			Server::get(IUserManager::class),
			$this->request(),
			Server::get(ITimeFactory::class),
		);
	}

	protected function changeLog(): SecurityChangeLog {
		return new SecurityChangeLog(
			Server::get(SecurityChangeMapper::class),
			$this->actors,
			$this->userSession,
			Server::get(ResetTracker::class),
			$this->currentSession,
			$this->addresses(),
			$this->dispatcher([AccountTakeoverDetector::class => $this->detector()], $this->takeoverEngine()),
			Server::get(ICrypto::class),
			Server::get(ITimeFactory::class),
			Server::get(LoggerInterface::class),
			$this->appSettings(),
		);
	}

	protected function listener(): SecurityChangeListener {
		return new SecurityChangeListener(
			$this->appSettings(),
			$this->changeLog(),
			Server::get(SecurityChangeMapper::class),
			Server::get(ResetTracker::class),
			Server::get(IRegistry::class),
			Server::get(ITimeFactory::class),
			Server::get(LoggerInterface::class),
		);
	}

	protected function accountLock(): AccountLock {
		return new AccountLock(
			$this->lockLinks(),
			Server::get(SecurityChangeMapper::class),
			Server::get(Tokens::class),
			$this->takeoverEngine(),
			Server::get(SecureAccountGuide::class),
			Server::get(IUserManager::class),
			$this->userSession,
			$this->addresses('198.51.100.20'),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
		);
	}

	/**
	 * Log the test session in as the account, as the actor the test chose.
	 *
	 * @param bool $risky whether the login needed a confirmation and was let in without one
	 * @return array{id: int, secret: string}
	 */
	protected function loginAs(IUser $user, bool $risky, ?int $at = null): array {
		$token = $this->startSession($user);
		$this->state->set(SessionState::CONFIRMATION, [
			'uid' => $user->getUID(),
			'by' => $risky ? 'none' : 'second_factor',
			'policies' => ['flagged_source'],
			'at' => $at ?? time(),
		]);
		return $token;
	}

	/**
	 * The changes the log holds for the account, made as the given way.
	 *
	 * @return list<array{id: int, uid: string, type: string, via: string, actor_uid: ?string, old_value_hint: ?string, new_value_hint: ?string, ref_id: ?int, detail: ?string, session_token_id: ?int, ip: ?string, created_at: int}>
	 */
	protected function changes(string $uid, ?string $via = SecurityChangeLog::VIA_SELF): array {
		$rows = Server::get(SecurityChangeMapper::class)->findSince($uid, 0, 100);
		return array_values(array_filter($rows, static fn (array $r): bool => $via === null || $r['via'] === $via));
	}
}
