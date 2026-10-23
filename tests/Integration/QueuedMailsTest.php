<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Mail\Message;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\SecondFactorFailed\SecondFactorFailed;
use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\LoginConfirmationStore;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Event\TypedEvents;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\AdminNotices;
use OCA\IntrusionDetection\Notification\Db\AlertMapper;
use OCA\IntrusionDetection\Notification\LoginNotices;
use OCA\IntrusionDetection\Notification\MailQueue;
use OCA\IntrusionDetection\Notification\MailReach;
use OCA\IntrusionDetection\Notification\Mails;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Response\Handlers\NotifyUserHandler;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\WasThisYou\Questions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJobList;
use OCP\Config\IUserConfig;
use OCP\IDateTimeFormatter;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Mail\IAttachment;
use OCP\Mail\IEMailTemplate;
use OCP\Mail\IEmailValidator;
use OCP\Mail\IMailer;
use OCP\Mail\IMessage;
use OCP\Notification\IManager as INotificationManager;
use OCP\Security\IHasher;
use OCP\Security\ISecureRandom;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Emails about detections go out from a background job, not in the request
 * that caused the detection; emails the user waits for go out at once.
 */
#[Group('DB')]
class QueuedMailsTest extends AccountTestCase {
	/** How long the mail server takes per email */
	private const SLOW_MAIL_SECONDS = 0.5;

	/** @var list<Message> */
	private array $delivered = [];

	public function testAUserAlertIsQueuedInTheRequestAndSentByTheJobInTheUsersTimeZone(): void {
		$user = $this->newUser('ids-queued', 'alice@example.com');
		$this->settingsEditor()->setResponses(SecondFactorFailed::ID, [ResponseType::NotifyUser]);
		Server::get(IUserConfig::class)->setValueString($user->getUID(), 'core', 'timezone', 'Pacific/Auckland');
		$alerts = $this->alertsWith($this->slowMails());

		$started = microtime(true);
		$detection = $this->engineWith($alerts)->handle(new DetectionDraft(SecondFactorFailed::ID, SourceKey::fromIp('198.51.100.7'), $user->getUID()));
		$request = microtime(true) - $started;

		$this->assertNotNull($detection);
		$this->assertSame([], $this->delivered, 'No email in the request');
		$this->assertLessThan(self::SLOW_MAIL_SECONDS, $request, 'The request does not wait for the mail server');
		$this->assertSame(UserAlerts::EMAIL_QUEUED, array_column($detection->getActionList(), null, 'type')['notify_user']['ref']['email']);
		$this->assertSame([['kind' => MailQueue::KIND_USER, 'detection' => $detection->getId(), 'uid' => $user->getUID()]], $this->queuedMails(), 'Only ids are queued');
		$this->assertCount(1, $this->notificationsFor($user->getUID(), UserAlerts::SUBJECT), 'The notification is not queued');

		$this->assertSame(1, $this->runQueuedMails($alerts));

		$this->assertSame([], $this->queuedMails(), 'The job ran once');
		$this->assertCount(1, $this->delivered);
		$message = $this->delivered[0];
		$this->assertSame(['alice@example.com' => $user->getDisplayName()], $message->getTo());
		$this->assertSame('Security notice: Someone entered your password, but not your second factor', $message->getSubject());
		$body = str_replace("\u{202F}", ' ', $message->getPlainBody());
		$when = Server::get(IDateTimeFormatter::class)->formatDateTime($detection->getCreatedAt(), 'long', 'short', new \DateTimeZone('Pacific/Auckland'), Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		$this->assertStringContainsString('This happened on ' . str_replace("\u{202F}", ' ', $when) . ', from the address 198.51.100.7.', $body, 'In the user\'s time zone');
		$this->assertStringContainsString('/settings/user/security#intrusion-detection', $body);
		$this->assertSame($this->mailOf($user->getUID(), $detection->getId()), $body, 'The same email as built in the request');
	}

	public function testTheLoginCodeIsSentAtOnce(): void {
		$user = $this->newUser('ids-queued', 'alice@example.com');
		$codes = new EmailCodes(
			Server::get(ISecureRandom::class),
			Server::get(IHasher::class),
			$this->slowMails(),
			Server::get(UserMessages::class),
			Server::get(ITimeFactory::class),
			Server::get(LoginConfirmationStore::class),
			Server::get(IUserConfig::class),
		);
		$state = new StepUpState($user->getUID(), ConfirmationStatus::Pending, ['protected_account'], time(), time() + 600, '198.51.100.7');

		$this->assertNotNull($codes->issue($user, $state)->codeHash);

		$this->assertCount(1, $this->delivered, 'Sent in the request the user waits in');
		$this->assertSame('Confirm your login', $this->delivered[0]->getSubject());
		$this->assertSame([], $this->queuedMails());
	}

	public function testEmailsToUsersAreCappedPerHourAcrossAllAccounts(): void {
		$now = time();
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(static function () use (&$now): int {
			return $now;
		});
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->exactly(2))->method('warning')->with($this->stringContains('{max} emails to users within the hour'));
		$queue = new MailQueue(Server::get(IJobList::class), Server::get(AlertMapper::class), $time, $logger);
		$shared = MailQueue::MAX_USER_MAILS_PER_HOUR - MailQueue::RESERVED_FOR_SEVERE;

		// An attacker walks 150 accounts within the hour.
		$queued = 0;
		for ($i = 1; $i <= 150; $i++) {
			$queued += $queue->user(1000000 + $i, 'walked-' . $i, Severity::Medium) ? 1 : 0;
		}
		$this->assertSame($shared, $queued, 'Lesser detections leave the reserve alone');
		$this->assertFalse($queue->shareOwners(1000001, Severity::Low), 'Share owners count against the same cap');

		// A takeover notice still gets out, until the reserve is used up too.
		$severe = 0;
		for ($i = 1; $i <= MailQueue::RESERVED_FOR_SEVERE + 5; $i++) {
			$severe += $queue->user(3000000 + $i, 'taken-' . $i, $i % 2 === 0 ? Severity::Critical : Severity::High) ? 1 : 0;
		}
		$this->assertSame(MailQueue::RESERVED_FOR_SEVERE, $severe);
		$this->assertFalse($queue->shareOwners(1000002, Severity::Critical));
		$this->assertCount(MailQueue::MAX_USER_MAILS_PER_HOUR, $this->queuedMails(), 'At most the cap of jobs');

		// Above the cap, a user is told inside Nextcloud and at the next login.
		$user = $this->newUser('ids-queued', 'alice@example.com');
		[$detection] = Server::get(DetectionService::class)->record(new DetectionDraft(SecondFactorFailed::ID, SourceKey::fromIp('198.51.100.7'), $user->getUID()), $this->checkSettings()->modeState(SecondFactorFailed::ID));
		$result = $this->alertsWith($this->mails, $queue)->notify($detection);
		$this->assertSame(['bell' => UserAlerts::BELL_SENT, 'email' => UserAlerts::EMAIL_LIMITED, 'admins' => 0], $result);
		$this->assertCount(1, $this->notificationsFor($user->getUID(), UserAlerts::SUBJECT));
		$this->assertSame($detection->getCreatedAt(), Server::get(LoginNotices::class)->since($user->getUID()));
		$this->assertCount(MailQueue::MAX_USER_MAILS_PER_HOUR, $this->queuedMails());

		// The administrators' alert is not capped here: it has its own hourly limit.
		$queue->admins(1000001);
		$this->assertCount(MailQueue::MAX_USER_MAILS_PER_HOUR + 1, $this->queuedMails());

		// The next hour, users are emailed again.
		$now += 3600;
		$this->assertTrue($queue->user(2000000, 'walked-next-hour', Severity::Low));
	}

	public function testAJobForADetectionOrAccountThatIsGoneSendsNothing(): void {
		$user = $this->newUser('ids-queued', 'alice@example.com');
		$this->settingsEditor()->setResponses(SecondFactorFailed::ID, [ResponseType::NotifyUser]);
		$alerts = $this->alertsWith($this->slowMails());
		$detection = $this->engineWith($alerts)->handle(new DetectionDraft(SecondFactorFailed::ID, SourceKey::fromIp('198.51.100.7'), $user->getUID()));
		$this->assertNotNull($detection);
		$this->engineWith($alerts)->handle(new DetectionDraft(SecondFactorFailed::ID, SourceKey::fromIp('198.51.100.8'), $user->getUID()));
		$this->assertCount(2, $this->queuedMails());

		$qb = $this->db->getQueryBuilder();
		$qb->delete('ids_detections')->where($qb->expr()->eq('id', $qb->createNamedParameter($detection->getId())))->executeStatement();
		Server::get(IUserManager::class)->get($user->getUID())?->setEnabled(false);

		$this->assertSame(2, $this->runQueuedMails($alerts));
		$this->assertSame([], $this->delivered);
		$this->assertSame([], $this->notificationsFor('admin', AdminNotices::SUBJECT_USER_UNREACHABLE));
	}

	/**
	 * The plain text of the email about a detection as it is built now.
	 */
	private function mailOf(string $uid, int $detectionId): string {
		$this->delivered = [];
		$user = Server::get(IUserManager::class)->get($uid);
		$this->assertNotNull($user);
		$detection = Server::get(\OCA\IntrusionDetection\Db\DetectionMapper::class)->findById($detectionId);
		$this->assertTrue($this->slowMails(0.0)->send($user, Server::get(UserMessages::class)->mail($detection, $user)));
		return str_replace("\u{202F}", ' ', $this->delivered[0]->getPlainBody());
	}

	private function alertsWith(Mails $mails, ?MailQueue $queue = null): UserAlerts {
		return new UserAlerts(
			Server::get(AlertMapper::class),
			Server::get(INotificationManager::class),
			$mails,
			Server::get(UserMessages::class),
			Server::get(AdminNotices::class),
			Server::get(IUserManager::class),
			Server::get(ITimeFactory::class),
			Server::get(LoginNotices::class),
			Server::get(Questions::class),
			$queue ?? Server::get(MailQueue::class),
			Server::get(CheckRegistry::class),
			Server::get(MailReach::class),
		);
	}

	private function engineWith(UserAlerts $alerts): ResponseEngine {
		return new ResponseEngine(
			Server::get(CheckRegistry::class),
			$this->checkSettings(),
			Server::get(DetectionService::class),
			new OverridingContainer([NotifyUserHandler::class => new NotifyUserHandler($alerts)]),
			Server::get(TypedEvents::class),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
		);
	}

	/**
	 * Core's mails and templates with a mail server that takes $seconds per
	 * email and keeps what it was given.
	 */
	private function slowMails(float $seconds = self::SLOW_MAIL_SECONDS): Mails {
		$real = Server::get(IMailer::class);
		$mailer = new class($real, $seconds, $this->delivered) implements IMailer {
			/**
			 * @param list<Message> $delivered
			 */
			public function __construct(
				private IMailer $real,
				private float $seconds,
				private array &$delivered,
			) {
			}

			public function createMessage(): IMessage {
				return $this->real->createMessage();
			}

			public function createAttachment($data = null, $filename = null, $contentType = null): IAttachment {
				return $this->real->createAttachment($data, $filename, $contentType);
			}

			public function createAttachmentFromPath(string $path, $contentType = null): IAttachment {
				return $this->real->createAttachmentFromPath($path, $contentType);
			}

			public function createEMailTemplate(string $emailId, array $data = []): IEMailTemplate {
				return $this->real->createEMailTemplate($emailId, $data);
			}

			public function send(IMessage $message): array {
				usleep((int)($this->seconds * 1000000));
				if ($message instanceof Message) {
					$this->delivered[] = $message;
				}
				return [];
			}

			public function validateMailAddress(string $email): bool {
				return $this->real->validateMailAddress($email);
			}
		};
		return new Mails($mailer, Server::get(IEmailValidator::class), Server::get(LoggerInterface::class));
	}
}
