<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\DecoyCredential;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce;
use OCA\IntrusionDetection\Check\Checks\TrapUrl;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\BlocklistStatMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\ProtectedAccountMapper;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\Notification\AdminRecipients;
use OCA\IntrusionDetection\Notification\Digest;
use OCA\IntrusionDetection\Notification\DigestSchedule;
use OCA\IntrusionDetection\Notification\DigestSender;
use OCA\IntrusionDetection\Notification\MailContent;
use OCA\IntrusionDetection\Notification\Mails;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IDateTimeZone;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Mail\IEMailTemplate;
use OCP\Mail\IEmailValidator;
use OCP\Mail\IMailer;
use OCP\Mail\IMessage;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * The admin digest (concept section 11.10): when it is sent, to whom, once
 * per period, and what it contains.
 */
#[Group('DB')]
class DigestTest extends IntegrationTestCase {
	/** Monday 19 October 2026, 08:00 UTC */
	private const DUE = 1792396800;
	private const DAY = 86400;

	private Settings $settings;
	private int $now = self::DUE + 1800;
	/** @var list<IUser> */
	private array $admins = [];
	/** @var list<array{string, MailContent}> */
	private array $mailed = [];
	private bool $mailWorks = true;
	private LoggerInterface&MockObject $logger;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = Server::get(Settings::class);
		$this->admins = [$this->admin('alice', 'alice@example.com'), $this->admin('bob', null), $this->admin('carol', 'not an address')];
		$this->logger = $this->createMock(LoggerInterface::class);
	}

	public function testTheDigestIsDueOnMondayAt0800(): void {
		$this->assertSame(self::DUE, (new DigestSchedule('weekly', new \DateTimeZone('UTC')))->lastDue($this->now));
		$this->assertSame('Monday 08:00', gmdate('l H:i', self::DUE));
	}

	public function testTheReportCollectsEverySectionOfThePeriod(): void {
		$this->seed();
		$report = $this->digest()->report($this->schedule(), self::DUE);

		$this->assertSame(self::DUE - 7 * self::DAY, $report->start);
		$this->assertSame(self::DUE, $report->end);
		$this->assertSame(self::DUE - 14 * self::DAY, $report->previousStart);
		$this->assertSame('weekly', $report->kind);

		$this->assertSame(['enforced' => 6, 'observed' => 0, 'previous' => 2], $report->checks[CredentialStuffing::ID]);
		$this->assertSame(['enforced' => 2, 'observed' => 0, 'previous' => 0], $report->checks[PasswordSpraying::ID]);
		$this->assertSame(['enforced' => 0, 'observed' => 1, 'previous' => 0], $report->checks[TrapUrl::ID]);
		$this->assertSame(CredentialStuffing::ID, array_key_first($report->checks), 'the busiest check first');
		$this->assertSame(14, $report->enforced);
		$this->assertSame(1, $report->observed);
		$this->assertSame(2, $report->previousDetections);
		$this->assertSame(3, $report->bans, 'two from detections and one by hand, not the one of the week before');

		$this->assertSame([
			['ip' => '198.51.100.7', 'detections' => 6, 'checks' => [CredentialStuffing::ID, PasswordSpraying::ID], 'bans' => 2],
			['ip' => '192.0.2.77', 'detections' => 2, 'checks' => [DecoyCredential::ID], 'bans' => 0],
		], array_slice($report->sources, 0, 2));
		$this->assertNotContains('203.0.113.250', array_column($report->sources, 'ip'), 'detections before the period are left out');

		$this->assertSame([['uid' => 'victim', 'detections' => 3]], $report->accounts);
		$this->assertSame([['label' => 'Backup script on nas01', 'detections' => 2, 'addresses' => 1, 'lastAt' => self::DUE - self::DAY]], $report->decoys);
		$this->assertSame([['shareId' => 987654, 'owner' => 'sharer', 'detections' => 1]], $report->shares);
		$this->assertSame([['id' => 'spamhaus_drop_v4', 'name' => 'Spamhaus DROP (IPv4)', 'matches' => 5]], $report->blocklists, 'days whose midnight is outside the period are left out');
		$this->assertSame(['protected'], array_column($report->protectedAccounts, 'uid'));
		$this->assertSame(['denier'], array_column($report->deniedByUsers, 'uid'));
		$this->assertFalse($report->isQuiet());
	}

	public function testTheWeekBeforeCountsWhenItsDetectionsAreDeletedAlready(): void {
		$this->seed();
		// A retention of seven days: the detections of the week before are gone.
		Server::get(DetectionTotals::class)->deleteCreatedBefore(self::DUE - 7 * self::DAY);
		$report = $this->digest()->report($this->schedule(), self::DUE);
		$this->assertSame(2, $report->previousDetections);
		$this->assertSame(['enforced' => 6, 'observed' => 0, 'previous' => 2], $report->checks[CredentialStuffing::ID]);
		$this->assertSame(14, $report->enforced);
	}

	public function testTheEmailHasASectionForEveryKindOfDataAndLeavesOutEmptyOnes(): void {
		$this->seed();
		$content = $this->digest()->content($this->digest()->report($this->schedule(), self::DUE), 'en');
		$this->assertSame('Intrusion detection weekly summary: 15 detections', $content->subject);
		$this->assertSame('Weekly security summary', $content->heading);
		$this->assertSame(['Detections per check', 'Most active addresses', 'Accounts under attack', 'Decoys that were used', 'Shares under attack', 'Blocklist matches', 'Open items'],
			array_map(static fn ($card): string => $card->getTitle(), $content->details));
		$this->assertSame('Protecting', $content->notes[0]['label']);
		$this->assertStringContainsString('15 detections in this period. Nextcloud acted on 14 and observed 1. The week before: 2 detections. 3 addresses or networks were blocked.', $content->paragraphs[1]);
		$this->assertStringEndsWith('/settings/admin/intrusion_detection', (string)$content->buttonUrl);

		$this->insertDetection(CredentialStuffing::ID, '198.51.100.8', null, self::DUE + 7 * self::DAY - 3600);
		$next = $this->digest()->content($this->digest()->report($this->schedule(), self::DUE + 7 * self::DAY), 'en');
		$this->assertSame(['Detections per check', 'Most active addresses', 'Open items'], array_map(static fn ($card): string => $card->getTitle(), $next->details));
	}

	public function testLearningModeAndProblemsAreShownOnTop(): void {
		$this->settings->setGlobal(GlobalSettings::LEARNING_UNTIL, time() + 3 * self::DAY + 3600);
		$content = $this->digest()->content($this->digest()->report($this->schedule(), self::DUE), 'en');
		$this->assertSame('Learning: 4 days left', $content->notes[0]['label']);
		$this->assertSame(IEMailTemplate::NOTE_INFO, $content->notes[0]['type']);

		$this->settings->setGlobal(GlobalSettings::LEARNING_UNTIL, 0);
		$this->settings->setGlobal(GlobalSettings::ENABLED, false);
		$content = $this->digest()->content($this->digest()->report($this->schedule(), self::DUE), 'en');
		$this->assertSame('Off', $content->notes[0]['label']);
		$this->assertSame(IEMailTemplate::NOTE_WARNING, $content->notes[0]['type']);
	}

	public function testEverythingInTheEmailIsEscaped(): void {
		$this->insertDetection(AccountUnderAttack::ID, null, '<script>alert(1)</script>', self::DUE - 3600);
		$this->insertDetection(DecoyCredential::ID, '192.0.2.1', null, self::DUE - 3600, ['decoy' => 1, 'label' => '<img src=x onerror=alert(2)>']);
		$content = $this->digest()->content($this->digest()->report($this->schedule(), self::DUE), 'en');

		$template = null;
		$mailer = $this->createMock(IMailer::class);
		$mailer->method('createEMailTemplate')->willReturnCallback(static fn (string $id, array $data) => Server::get(IMailer::class)->createEMailTemplate($id, $data));
		$message = $this->createMock(IMessage::class);
		$message->method('setTo')->willReturnSelf();
		$message->method('useTemplate')->willReturnCallback(function ($t) use (&$template, $message) {
			$template = $t;
			return $message;
		});
		$mailer->method('createMessage')->willReturn($message);
		$mailer->method('send')->willReturn([]);
		$mails = new Mails($mailer, Server::get(IEmailValidator::class), $this->logger);
		$this->assertTrue($mails->send($this->admins[0], $content));

		$this->assertInstanceOf(IEMailTemplate::class, $template);
		$html = $template->renderHtml();
		$this->assertStringNotContainsString('<script>alert(1)', $html);
		$this->assertStringNotContainsString('<img src=x', $html);
		$this->assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $html);
		$this->assertStringContainsString('&lt;img src=x onerror=alert(2)&gt;', $html);
		$text = $template->renderText();
		$this->assertStringContainsString('Accounts under attack', $text);
		$this->assertStringContainsString('<script>alert(1)</script>: 1 detection', $text, 'the plain-text part has the same content');
	}

	public function testAQuietPeriodSendsAShortEmail(): void {
		$this->assertSame(DigestSender::RESULT_SENT, $this->sender()->sendIfDue());
		$this->assertCount(1, $this->mailed);
		$content = $this->mailed[0][1];
		$this->assertSame('Intrusion detection weekly summary: nothing happened', $content->subject);
		$this->assertSame([], $content->details);
		$this->assertStringContainsString('Nothing happened', implode(' ', $content->paragraphs));
	}

	public function testQuietDigestsCanBeTurnedOff(): void {
		$this->settings->setGlobal(GlobalSettings::DIGEST_SEND_QUIET, false);
		$this->assertSame(DigestSender::RESULT_QUIET_SKIPPED, $this->sender()->sendIfDue());
		$this->assertSame([], $this->mailed);
		$this->assertSame(DigestSender::RESULT_ALREADY_SENT, $this->sender()->sendIfDue(), 'the period is done');

		// A period with something in it is still sent.
		$this->insertDetection(CredentialStuffing::ID, '198.51.100.7', null, self::DUE + 3 * self::DAY);
		$this->now = self::DUE + 7 * self::DAY + 60;
		$this->assertSame(DigestSender::RESULT_SENT, $this->sender()->sendIfDue());
	}

	public function testOnlyAdminsWithAnEmailAddressGetIt(): void {
		$this->assertSame(DigestSender::RESULT_SENT, $this->sender()->sendIfDue());
		$this->assertSame(['alice'], array_column($this->mailed, 0));
		$state = $this->settings->getJson(GlobalSettings::DIGEST_STATE);
		$this->assertSame(['period' => self::DUE, 'sentAt' => $this->now, 'result' => 'sent', 'recipients' => 1, 'failed' => 0, 'withoutEmail' => 2], $state);

		$overview = $this->sender()->overview($this->admins[1]);
		$this->assertSame(1, $overview['recipients']);
		$this->assertSame(2, $overview['withoutEmailCount']);
		$this->assertSame(['bob', 'carol'], array_column($overview['withoutEmail'], 'uid'));
		$this->assertFalse($overview['viewerHasEmail']);
		$this->assertSame(self::DUE + 7 * self::DAY, $overview['nextDue']);
		$this->assertSame(['period' => self::DUE, 'sentAt' => $this->now, 'result' => 'sent', 'recipients' => 1, 'failed' => 0], $overview['last']);
	}

	public function testWithoutAnyAddressNothingIsSent(): void {
		$this->admins = [$this->admin('bob', null)];
		$this->assertSame(DigestSender::RESULT_NO_RECIPIENTS, $this->sender()->sendIfDue());
		$this->assertSame([], $this->mailed);
	}

	public function testItIsSentOncePerPeriodAlsoFromAnotherServer(): void {
		$this->assertSame(DigestSender::RESULT_SENT, $this->sender()->sendIfDue());
		$this->now += 3600;
		$this->assertSame(DigestSender::RESULT_ALREADY_SENT, $this->sender()->sendIfDue());
		// Another web server whose settings cache has not seen the new state yet still finds the claim.
		$this->settings->setGlobal(GlobalSettings::DIGEST_STATE, '{}');
		$this->assertSame(DigestSender::RESULT_ALREADY_SENT, $this->sender()->sendIfDue());
		$this->assertCount(1, $this->mailed);
	}

	public function testOfTwoConcurrentRunsOnlyOneSends(): void {
		// The other run claimed the period between this run's state check and its claim.
		$first = $this->sender();
		$second = $this->sender();
		[, $claimed] = Server::get(AlertMapper::class)->hit(DigestSender::CLAIM_CHECK, DigestSender::CLAIM_SOURCE, intdiv(self::DUE, 3600), null, $this->now);
		$this->assertTrue($claimed);
		$this->assertSame(DigestSender::RESULT_ALREADY_SENT, $first->sendIfDue());
		$this->assertSame(DigestSender::RESULT_ALREADY_SENT, $second->sendIfDue());
		$this->assertSame([], $this->mailed);
	}

	public function testOffLateAndBeforeInstallationNothingIsSent(): void {
		$this->settings->setGlobal(GlobalSettings::DIGEST_FREQUENCY, 'off');
		$this->assertSame(DigestSender::RESULT_OFF, $this->sender()->sendIfDue());
		$this->settings->setGlobal(GlobalSettings::DIGEST_FREQUENCY, 'weekly');

		$this->now = self::DUE + DigestSchedule::GRACE + 1;
		$this->assertSame(DigestSender::RESULT_NOT_DUE, $this->sender()->sendIfDue(), 'cron did not run for half a day: this digest is skipped');

		$this->now = self::DUE + 1800;
		$this->settings->setGlobal(GlobalSettings::INSTALLED_AT, self::DUE + 60);
		$this->assertSame(DigestSender::RESULT_NOT_DUE, $this->sender()->sendIfDue(), 'no digest for a week before the app was installed');
		$this->assertSame([], $this->mailed);
	}

	public function testDailyDigestsAreDueEveryDay(): void {
		$this->now = self::DUE + self::DAY + 600;
		$this->assertSame(DigestSender::RESULT_NOT_DUE, $this->sender()->sendIfDue(), 'Tuesday is not a weekly digest day');
		$this->settings->setGlobal(GlobalSettings::DIGEST_FREQUENCY, 'daily');
		$this->insertDetection(CredentialStuffing::ID, '198.51.100.7', null, self::DUE + 3600);
		$this->assertSame(DigestSender::RESULT_SENT, $this->sender()->sendIfDue());
		$this->assertSame('Intrusion detection daily summary: 1 detection', $this->mailed[0][1]->subject);
		$this->assertSame('Daily security summary', $this->mailed[0][1]->heading);
	}

	public function testAFailingMailServerIsRecordedAndLogged(): void {
		$this->mailWorks = false;
		$this->logger->expects($this->once())->method('error');
		$this->assertSame(DigestSender::RESULT_FAILED, $this->sender()->sendIfDue());
		$this->assertSame('failed', $this->settings->getJson(GlobalSettings::DIGEST_STATE)['result']);
	}

	public function testTheTestDigestGoesOnlyToTheAdminWhoAskedAndChangesNothing(): void {
		$this->insertDetection(CredentialStuffing::ID, '198.51.100.7', null, $this->now - 600);
		$this->assertSame(DigestSender::TEST_SENT, $this->sender()->sendTest($this->admins[0]));
		$this->assertSame(['alice'], array_column($this->mailed, 0));
		$content = $this->mailed[0][1];
		$this->assertStringStartsWith('Test: ', $content->subject);
		$this->assertSame('Test', $content->notes[0]['label']);
		$this->assertStringContainsString('sent only to you', $content->notes[0]['text']);
		$this->assertStringContainsString('1 detection in this period.', implode(' ', $content->paragraphs), 'the period up to now');
		$this->assertSame([], $this->settings->getJson(GlobalSettings::DIGEST_STATE));

		$this->assertSame(DigestSender::TEST_NO_ADDRESS, $this->sender()->sendTest($this->admins[1]));
		$this->assertCount(1, $this->mailed);
		$this->assertSame(DigestSender::RESULT_SENT, $this->sender()->sendIfDue(), 'the real digest is still sent');
		$this->assertCount(2, $this->mailed);
	}

	private function schedule(): DigestSchedule {
		return new DigestSchedule((string)$this->settings->global(GlobalSettings::DIGEST_FREQUENCY), new \DateTimeZone('UTC'));
	}

	private function digest(): Digest {
		return Server::get(Digest::class);
	}

	private function sender(): DigestSender {
		$recipients = $this->createMock(AdminRecipients::class);
		$recipients->method('users')->willReturnCallback(fn (): array => $this->admins);
		$mails = $this->createMock(Mails::class);
		$mails->method('send')->willReturnCallback(function (IUser $user, MailContent $content): bool {
			if (!$this->mailWorks) {
				return false;
			}
			$this->mailed[] = [$user->getUID(), $content];
			return true;
		});
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		$timezone = $this->createMock(IDateTimeZone::class);
		$timezone->method('getDefaultTimeZone')->willReturn(new \DateTimeZone('UTC'));
		return new DigestSender(
			$this->settings,
			$this->digest(),
			$recipients,
			$mails,
			Server::get(AlertMapper::class),
			Server::get(IEmailValidator::class),
			Server::get(IFactory::class),
			$timezone,
			Server::get(Prerequisites::class),
			$time,
			$this->logger,
		);
	}

	/**
	 * A week with something in every section, plus data before and after it.
	 */
	private function seed(): void {
		$week = self::DUE - 7 * self::DAY;
		for ($i = 0; $i < 6; $i++) {
			$detection = $this->insertDetection($i < 4 ? CredentialStuffing::ID : PasswordSpraying::ID, '198.51.100.7', null, $week + $i * 3600);
			if ($i < 2) {
				$this->insertBan($detection, $week + $i * 3600);
			}
		}
		$this->insertDetection(CredentialStuffing::ID, '198.51.100.8', null, $week + self::DAY);
		$this->insertDetection(CredentialStuffing::ID, '198.51.100.9', null, $week + self::DAY);
		$this->insertDetection(TrapUrl::ID, '203.0.113.9', null, $week + 2 * self::DAY, enforced: false);
		for ($i = 0; $i < 3; $i++) {
			$this->insertDetection(AccountUnderAttack::ID, null, 'victim', $week + $i * self::DAY);
		}
		$facts = ['decoy' => 3, 'label' => 'Backup script on nas01', 'format' => 'app_password', 'match' => 'secret'];
		$this->insertDetection(DecoyCredential::ID, '192.0.2.77', null, self::DUE - 2 * self::DAY, $facts);
		$this->insertDetection(DecoyCredential::ID, '192.0.2.77', null, self::DUE - self::DAY, $facts);
		$this->insertDetection(ShareBruteforce::ID, null, 'sharer', $week + 3 * self::DAY, ['rule' => 'password_share'], 987654);
		$manual = new Ban();
		$manual->setReference('MANUAL01');
		$manual->setCidr('192.0.2.99/32');
		$manual->setScope(Ban::SCOPE_IP);
		$manual->setBanKey('192.0.2.99');
		$manual->setLevel(1);
		$manual->setCheckId('manual');
		$manual->setCreatedAt($week + 4 * self::DAY);
		$manual->setExpiresAt($week + 5 * self::DAY);
		Server::get(BanMapper::class)->insert($manual);

		// The week before
		$old = $this->insertDetection(CredentialStuffing::ID, '203.0.113.250', null, $week - self::DAY);
		$this->insertBan($old, $week - self::DAY);
		$this->insertDetection(CredentialStuffing::ID, '203.0.113.251', null, $week - 2 * self::DAY);
		// After the period
		$this->insertDetection(CredentialStuffing::ID, '203.0.113.252', null, self::DUE + 60);

		$stats = Server::get(BlocklistStatMapper::class);
		for ($i = 0; $i < 4; $i++) {
			$stats->record('spamhaus_drop_v4', gmdate('Y-m-d', $week + self::DAY), '203.0.113.' . $i);
		}
		// The day the digest is due started within the period; the next one does not.
		$stats->record('spamhaus_drop_v4', gmdate('Y-m-d', self::DUE), '203.0.113.200');
		$stats->record('spamhaus_drop_v4', gmdate('Y-m-d', $week), '203.0.113.201');
		$stats->record('spamhaus_drop_v4', gmdate('Y-m-d', self::DUE + 8 * self::DAY), '203.0.113.202');

		Server::get(ProtectedAccountMapper::class)->protect('protected', AccountUnderAttack::ID, null, time(), time() + self::DAY);

		$denied = $this->insertDetection(CredentialStuffing::ID, '198.51.100.20', 'denier', $week - 10 * self::DAY);
		$denied->setUserVerdict(Detection::VERDICT_DENIED);
		$denied->setVerdictAt($week + self::DAY);
		Server::get(DetectionMapper::class)->update($denied);
	}

	/**
	 * @param array<string, mixed> $facts
	 */
	private function insertDetection(string $checkId, ?string $ip, ?string $uid, int $at, array $facts = [], ?int $shareId = null, bool $enforced = true): Detection {
		$detection = new Detection();
		$detection->setCheckId($checkId);
		$detection->setSeverity('medium');
		$detection->setEnforced($enforced);
		$detection->setIp($ip);
		$detection->setUid($uid);
		$detection->setShareId($shareId);
		$detection->setExplanationData(['facts' => $facts]);
		$detection->setActionList([['type' => 'ban', 'enforced' => $enforced]]);
		$detection->setCreatedAt($at);
		$detection->setLastSeenAt($at);
		$detection->setHits(1);
		$detection = Server::get(DetectionMapper::class)->insert($detection);
		Server::get(DetectionTotals::class)->created($detection);
		return $detection;
	}

	private function insertBan(Detection $detection, int $at): void {
		$ban = new Ban();
		$ban->setReference(strtoupper(substr(bin2hex(random_bytes(4)), 0, 8)));
		$ban->setCidr($detection->getIp() . '/32');
		$ban->setScope(Ban::SCOPE_IP);
		$ban->setBanKey((string)$detection->getIp());
		$ban->setLevel(1);
		$ban->setCheckId($detection->getCheckId());
		$ban->setDetectionId($detection->getId());
		$ban->setCreatedAt($at);
		$ban->setExpiresAt($at + 14400);
		Server::get(BanMapper::class)->insert($ban);
	}

	private function admin(string $uid, ?string $email): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($uid);
		$user->method('getEMailAddress')->willReturn($email);
		$user->method('getDisplayName')->willReturn(ucfirst($uid));
		return $user;
	}
}
