<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack;
use OCA\IntrusionDetection\Check\Checks\SecondFactorFailed;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\AdminNotices;
use OCA\IntrusionDetection\Notification\LoginNotices;
use OCA\IntrusionDetection\Notification\Mails;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;
use OCP\IDateTimeFormatter;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Mail\IEmailValidator;
use OCP\Mail\IMailer;
use OCP\Mail\IMessage;
use OCP\Notification\AlreadyProcessedException;
use OCP\Notification\IManager as INotificationManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Telling the affected user (concept section 11.1): what they are told,
 * by which channel, how often, and what happens for users without email.
 */
#[Group('DB')]
class UserAlertsTest extends AccountTestCase {
	private const USER_AGENT = "Mozilla/5.0 <script>alert(1)</script>\x07 ";

	private DetectionService $detections;
	private int $now;

	protected function setUp(): void {
		parent::setUp();
		$this->detections = Server::get(DetectionService::class);
		$this->now = time();
	}

	public function testTheUserGetsANotificationAndAnEmailAboutWhatHappenedAndWhatWasDone(): void {
		$user = $this->newUser('ids-notify', 'alice@example.com');
		Server::get(IUserConfig::class)->setValueString($user->getUID(), 'core', 'timezone', 'Pacific/Auckland');
		$detection = $this->detection($user, SecondFactorFailed::ID, [
			['type' => ResponseType::KillSession->value, 'enforced' => true, 'ref' => ['session' => ['id' => 5, 'name' => 'Firefox'], 'tokens' => [], 'loggedOut' => true]],
			['type' => ResponseType::ForcePasswordChange->value, 'enforced' => true, 'ref' => ['uid' => $user->getUID(), 'state' => PasswordChangeService::STATE_REQUIRED]],
			['type' => ResponseType::NotifyAdmin->value, 'enforced' => false],
		], userAgent: self::USER_AGENT . str_repeat('x', 400));

		$result = $this->alerts()->notify($detection);

		$this->assertSame(['bell' => UserAlerts::BELL_SENT, 'email' => UserAlerts::EMAIL_SENT, 'admins' => 0], $result);
		$bells = $this->notificationsFor($user->getUID(), UserAlerts::SUBJECT);
		$this->assertCount(1, $bells);
		$this->assertSame(['detection' => $detection->getId()], $bells[0]->getSubjectParameters(), 'The notification carries only the id');
		$this->assertCount(1, $this->mailed);
		$mail = $this->mailed[0][1];
		$this->assertSame('Security notice: Someone entered your password, but not your second factor', $mail->subject);
		$when = Server::get(IDateTimeFormatter::class)->formatDateTime($detection->getCreatedAt(), 'long', 'short', new \DateTimeZone('Pacific/Auckland'), Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		$whenParagraph = (string)($mail->paragraphs[count($mail->paragraphs) - 1] ?? '');
		$this->assertStringStartsWith('This happened on ' . $when . ', from the address 198.51.100.7, with "Mozilla/5.0 <script>alert(1)</script>', $whenParagraph, 'In the user\'s time zone');
		$this->assertTrue(preg_match('/with "(.*)"\.$/', $whenParagraph, $match) === 1);
		$this->assertLessThanOrEqual(UserMessages::MAX_USER_AGENT, mb_strlen($match[1]), 'A short user agent');
		$this->assertStringNotContainsString("\x07", $whenParagraph);
		$this->assertSame(['The suspicious session was ended.', 'You will be asked to choose a new password the next time you log in.'], $mail->listItems, 'Only what was really done');
		$this->assertStringContainsString('Choose a new password when you are asked at your next login', implode(' ', $mail->closing));
		$this->assertSame(Server::get(\OCP\IURLGenerator::class)->linkToRouteAbsolute('settings.PersonalSettings.index', ['section' => 'security']) . '#intrusion-detection', $mail->buttonUrl);
		$this->assertStringNotContainsString((string)$detection->getId(), (string)$mail->buttonUrl, 'The link carries no id or token');

		// The bell shows the same, rendered for its own recipient only.
		$prepared = Server::get(Notifier::class)->prepare($bells[0], 'en');
		$this->assertSame('Someone entered your password, but not your second factor', $prepared->getParsedSubject());
		$this->assertStringContainsString('The suspicious session was ended.', $prepared->getParsedMessage());
		$this->assertSame($mail->buttonUrl, $prepared->getLink());
		$foreign = Server::get(INotificationManager::class)->createNotification();
		$foreign->setApp(Application::APP_ID)->setUser('someone-else')->setDateTime(new \DateTime())->setObject(UserAlerts::OBJECT_TYPE, (string)$detection->getId())->setSubject(UserAlerts::SUBJECT, ['detection' => $detection->getId()]);
		$this->expectException(AlreadyProcessedException::class);
		Server::get(Notifier::class)->prepare($foreign, 'en');
	}

	public function testTheEmailIsEscapedAndHasNoControlCharacters(): void {
		$user = $this->newUser('ids-notify', 'alice@example.com');
		$detection = $this->detection($user, SecondFactorFailed::ID, [], userAgent: self::USER_AGENT);
		$sent = null;
		$mailer = $this->createMock(IMailer::class);
		$mailer->method('createEMailTemplate')->willReturnCallback(static fn (string $id, array $data) => Server::get(IMailer::class)->createEMailTemplate($id, $data));
		$message = $this->createMock(IMessage::class);
		$message->method('setTo')->willReturnSelf();
		$message->method('useTemplate')->willReturnCallback(function ($template) use (&$sent, $message) {
			$sent = $template;
			return $message;
		});
		$mailer->method('createMessage')->willReturn($message);
		$mailer->method('send')->willReturn([]);
		$mails = new Mails($mailer, Server::get(IEmailValidator::class), Server::get(LoggerInterface::class));

		$this->assertTrue($mails->send($user, Server::get(UserMessages::class)->mail($detection, $user)));
		$this->assertNotNull($sent);
		$html = $sent->renderHtml();
		$this->assertStringNotContainsString('<script>', $html);
		$this->assertStringContainsString('&lt;script&gt;', $html);
		$this->assertStringNotContainsString("\x07", $sent->renderText());
	}

	public function testOneNotificationPerCheckAndUserAndHour(): void {
		$user = $this->newUser('ids-notify', 'alice@example.com');
		$first = $this->alerts()->notify($this->detection($user, SecondFactorFailed::ID));
		$second = $this->alerts()->notify($this->detection($user, SecondFactorFailed::ID, ip: '198.51.100.8'));
		$this->assertSame(UserAlerts::BELL_SENT, $first['bell'] ?? null);
		$this->assertSame(['bell' => UserAlerts::BELL_AGGREGATED, 'email' => UserAlerts::EMAIL_AGGREGATED, 'admins' => 0], $second);
		$this->assertCount(1, $this->notificationsFor($user->getUID(), UserAlerts::SUBJECT));
		$this->assertCount(1, $this->mailed);

		// Another check is told separately.
		$this->alerts()->notify($this->detection($user, AccountUnderAttack::ID, ip: null));
		$this->assertCount(2, $this->mailed);

		// The next hour, again.
		$this->now += 3600;
		$this->alerts()->notify($this->detection($user, SecondFactorFailed::ID));
		$this->assertCount(3, $this->mailed);
	}

	public function testAnAccountUnderAttackIsToldOnceADay(): void {
		$user = $this->newUser('ids-notify', 'alice@example.com');
		$this->now = intdiv(time(), 86400) * 86400 + 3600;
		$this->alerts()->notify($this->detection($user, AccountUnderAttack::ID, ip: null));
		$this->now += 6 * 3600;
		$this->alerts()->notify($this->detection($user, AccountUnderAttack::ID, ip: null));
		$this->assertCount(1, $this->mailed);
		$this->now += 86400;
		$this->alerts()->notify($this->detection($user, AccountUnderAttack::ID, ip: null));
		$this->assertCount(2, $this->mailed);
	}

	public function testUsersWithoutEmailAreToldInsideNextcloudAndTheAdminsLearnOfItForSevereDetections(): void {
		$user = $this->newUser('ids-noemail');
		$severe = $this->alerts()->notify($this->detection($user, SecondFactorFailed::ID));
		$this->assertSame(UserAlerts::EMAIL_NO_ADDRESS, $severe['email'] ?? null);
		$this->assertGreaterThan(0, $severe['admins'] ?? 0);
		$this->assertCount(1, $this->notificationsFor($user->getUID(), UserAlerts::SUBJECT));
		$this->assertSame([], $this->mailed, 'No email is sent');
		$notices = $this->notificationsFor('admin', AdminNotices::SUBJECT_USER_UNREACHABLE);
		$this->assertCount(1, $notices);
		$prepared = Server::get(Notifier::class)->prepare($notices[0], 'en');
		$this->assertSame($user->getUID() . ' has no email address, so they could only be told inside Nextcloud: Someone entered your password, but not your second factor If it matters, reach out to them another way.', $prepared->getParsedMessage());

		// Less severe detections only ring the bell.
		$medium = $this->alerts()->notify($this->detection($user, AccountUnderAttack::ID, ip: null));
		$this->assertSame(0, $medium['admins'] ?? null);
		$this->assertCount(1, $this->notificationsFor('admin', AdminNotices::SUBJECT_USER_UNREACHABLE));
	}

	public function testAFailingMailServerIsTreatedLikeAMissingAddress(): void {
		$user = $this->newUser('ids-notify', 'alice@example.com');
		$this->mailWorks = false;
		$result = $this->alerts()->notify($this->detection($user, SecondFactorFailed::ID));
		$this->assertSame(UserAlerts::EMAIL_FAILED, $result['email'] ?? null);
		$notices = $this->notificationsFor('admin', AdminNotices::SUBJECT_USER_UNREACHABLE);
		$this->assertCount(1, $notices);
		$this->assertSame(AdminNotices::REASON_MAIL_FAILED, $notices[0]->getSubjectParameters()['reason']);
	}

	public function testDisabledAndUnknownAccountsAreNotTold(): void {
		$user = $this->newUser('ids-notify', 'alice@example.com');
		$detection = $this->detection($user, SecondFactorFailed::ID);
		$user->setEnabled(false);
		$this->assertNull($this->alerts()->notify($detection));
		$detection->setUid('no-such-user-' . $user->getUID());
		$this->assertNull($this->alerts()->notify($detection));
		$this->assertSame([], $this->mailed);
	}

	public function testTheResponseRunsLastAndIsOnlyEnforcedInProtect(): void {
		$user = $this->newUser('ids-notify', 'alice@example.com');
		$this->settings->setMode(SecondFactorFailed::ID, Mode::Observe);
		$this->engine()->handle(new DetectionDraft(SecondFactorFailed::ID, SourceKey::fromIp('198.51.100.7'), $user->getUID()), [ResponseType::NotifyUser]);
		$this->assertSame([], $this->mailed, 'Observe tells nobody');
	}

	/**
	 * @param list<array{type: string, enforced: bool, ref?: mixed}> $actions
	 */
	private function detection(IUser $user, string $checkId, array $actions = [], ?string $ip = '198.51.100.7', ?string $userAgent = null): Detection {
		[$detection] = $this->detections->record(new DetectionDraft(
			checkId: $checkId,
			source: $ip === null ? null : SourceKey::fromIp($ip),
			uid: $user->getUID(),
			facts: ['provider' => 'totp', 'providerName' => 'TOTP'],
			userAgent: $userAgent,
		), new ModeState(Mode::Protect, Mode::Protect));
		$this->detections->setActions($detection, $actions);
		return $detection;
	}

	private function alerts(): UserAlerts {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		$time->method('getDateTime')->willReturnCallback(fn (): \DateTime => new \DateTime('@' . $this->now));
		return new UserAlerts(
			Server::get(AlertMapper::class),
			Server::get(INotificationManager::class),
			$this->mails,
			Server::get(UserMessages::class),
			new AdminNotices(Server::get(AlertMapper::class), Server::get(\OCA\IntrusionDetection\Notification\AdminRecipients::class), Server::get(INotificationManager::class), $time),
			Server::get(IUserManager::class),
			$time,
			Server::get(LoginNotices::class),
		);
	}
}
