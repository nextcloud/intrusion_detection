<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\SecondFactorFailed;
use OCA\IntrusionDetection\Check\Checks\SecondFactorFailedDetector;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\PasswordChangeFlag;
use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCP\Authentication\Token\IToken;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Concept section 10.4, with real session tokens and app passwords.
 */
#[Group('DB')]
class SecondFactorFailedTest extends AccountTestCase {
	private const ADDRESS = '198.51.100.7';

	private SecondFactorFailedDetector $detector;
	private IUser $user;
	private DetectionMapper $detections;

	protected function setUp(): void {
		parent::setUp();
		$this->detections = Server::get(DetectionMapper::class);
		$this->detector = new SecondFactorFailedDetector(
			$this->settings,
			Server::get(AttemptRecorder::class),
			Server::get(AttemptMapper::class),
			Server::get(FlaggedSources::class),
			$this->engine(),
			$this->currentSession,
			$this->session,
			Server::get(LoggerInterface::class),
		);
		$this->user = $this->newUser('ids-2fa', 'victim@example.com');
	}

	public function testOneOrTwoMistypedCodesDoNotFire(): void {
		$this->startSession($this->user);
		$this->assertFalse($this->failChallenge(), 'One typo never fires');
		$this->assertFalse($this->failChallenge());
		$this->assertSame([], $this->detectionsOfCheck());
		$this->assertSame(2, Server::get(AttemptMapper::class)->stats('uid', [$this->user->getUID()], [AttemptKind::SecondFactor], time() - 60)->failures);
		$this->assertFalse(Server::get(PasswordChangeFlag::class)->isRequired($this->user->getUID()));
	}

	public function testThreeFailuresInOneLoginEndOnlyThatSessionAndWhatCameWithIt(): void {
		$other = $this->token($this->user, IToken::TEMPORARY_TOKEN, 'Safari on the phone');
		$pending = $this->startSession($this->user, 'Firefox on Linux');
		$origins = Server::get(TokenOriginMapper::class);
		$fromSession = $this->token($this->user, IToken::PERMANENT_TOKEN, 'Created in the pending session');
		$origins->record($fromSession['id'], $this->user->getUID(), '203.0.113.50', $pending['id'], time());
		$sameAddress = $this->token($this->user, IToken::PERMANENT_TOKEN, 'Same address, recently');
		$origins->record($sameAddress['id'], $this->user->getUID(), self::ADDRESS, null, time() - 600);
		$sameAddressOld = $this->token($this->user, IToken::PERMANENT_TOKEN, 'Same address, two hours ago');
		$origins->record($sameAddressOld['id'], $this->user->getUID(), self::ADDRESS, null, time() - 7200);
		$elsewhere = $this->token($this->user, IToken::PERMANENT_TOKEN, 'Desktop client at home');
		$origins->record($elsewhere['id'], $this->user->getUID(), '192.0.2.10', $other['id'], time() - 600);
		$this->userSession->expects($this->once())->method('logout');

		$this->assertFalse($this->failChallenge());
		$this->assertFalse($this->failChallenge());
		$this->assertTrue($this->failChallenge(), 'The third failure in one login fires');

		$detections = $this->detectionsOfCheck();
		$this->assertCount(1, $detections);
		$detection = $detections[0];
		$this->assertTrue($detection->isEnforced());
		$this->assertSame('high', $detection->getSeverity());
		$this->assertSame($this->user->getUID(), $detection->getUid());
		$this->assertSame(self::ADDRESS, $detection->getIp());
		$facts = $detection->getExplanationData()['facts'];
		$this->assertSame([SecondFactorFailed::RULE_LOGIN], $facts['rules']);
		$this->assertSame(3, $facts['loginFailures']);
		$this->assertSame($pending['id'], $facts['sessionTokenId']);

		// Only the pending session and the app passwords that came with it are gone.
		$this->assertFalse($this->tokenExists($pending['id']), 'The pending session is ended');
		$this->assertFalse($this->tokenExists($fromSession['id']), 'An app password created from it is revoked');
		$this->assertFalse($this->tokenExists($sameAddress['id']), 'An app password from the same address within the hour is revoked');
		$this->assertTrue($this->tokenExists($sameAddressOld['id']), 'Older app passwords from that address keep working');
		$this->assertTrue($this->tokenExists($elsewhere['id']), 'App passwords from elsewhere keep working');
		$this->assertTrue($this->tokenExists($other['id']), 'The account\'s other sessions keep working');

		$actions = array_column($detection->getActionList(), null, 'type');
		$this->assertSame(['ban', 'kill_session', 'force_password_change', 'notify_admin', 'notify_user'], array_keys($actions));
		$kill = $actions['kill_session'];
		$this->assertTrue($kill['enforced']);
		$this->assertSame(['id' => $pending['id'], 'name' => 'Firefox on Linux'], $kill['ref']['session']);
		$this->assertTrue($kill['ref']['loggedOut']);
		$this->assertEqualsCanonicalizing(
			[['id' => $fromSession['id'], 'name' => 'Created in the pending session'], ['id' => $sameAddress['id'], 'name' => 'Same address, recently']],
			$kill['ref']['tokens'],
		);
		$this->assertTrue($actions['ban']['enforced']);
		$this->assertSame(PasswordChangeService::STATE_REQUIRED, $actions['force_password_change']['ref']['state']);
		$this->assertTrue(Server::get(PasswordChangeFlag::class)->isRequired($this->user->getUID()));
		$this->assertSame(UserAlerts::EMAIL_SENT, $actions['notify_user']['ref']['email']);

		// The user is told what happened and what was done.
		$this->assertCount(1, $this->notificationsFor($this->user->getUID(), UserAlerts::SUBJECT));
		$this->assertCount(1, $this->mailed);
		[$to, $mail] = $this->mailed[0];
		$this->assertSame($this->user->getUID(), $to);
		$this->assertStringContainsString('could not confirm it with your second factor', implode(' ', $mail->paragraphs));
		$done = implode(' ', $mail->listItems);
		$this->assertStringContainsString('The suspicious session was ended.', $done);
		$this->assertStringContainsString('2 app passwords that came with it were revoked.', $done);
		$this->assertStringContainsString('The address 198.51.100.7/32 was blocked.', $done);
		$this->assertStringContainsString('choose a new password the next time you log in', $done);

		// The administrators' narrative explains it.
		$narrative = Server::get(NarrativeBuilder::class)->build($detection, Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		$text = implode(' ', array_merge($narrative->happened, $narrative->done));
		$this->assertStringContainsString('entered the correct password from 198.51.100.7, but the second factor (TOTP) failed.', $text);
		$this->assertStringContainsString('The limit at that time was 3 failures in one login.', $text);
		$this->assertStringContainsString('Ended the session "Firefox on Linux"', $text);
		$this->assertStringContainsString('must choose a new password at the next login', $text);
	}

	public function testARepeatFromTheSameAddressJoinsTheDetectionAndEndsTheNewSessionToo(): void {
		$first = $this->startSession($this->user);
		$this->failChallenge();
		$this->failChallenge();
		$this->failChallenge();
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp(self::ADDRESS), FlaggedSources::REASON_ATTACK);
		$second = $this->startSession($this->user);
		$this->assertTrue($this->failChallenge());

		$detections = $this->detectionsOfCheck();
		$this->assertCount(1, $detections, 'One detection for the address and account');
		$this->assertSame(2, $detections[0]->getHits());
		$this->assertFalse($this->tokenExists($first['id']));
		$this->assertFalse($this->tokenExists($second['id']));
		$kill = array_column($detections[0]->getActionList(), null, 'type')['kill_session'];
		$this->assertSame($second['id'], $kill['ref']['session']['id']);
		$this->assertCount(1, $this->mailed, 'The user is told once within the hour');
	}

	public function testANewLoginStartsCountingAgain(): void {
		$this->startSession($this->user);
		$this->failChallenge();
		$this->failChallenge();
		$this->startSession($this->user);
		$this->assertFalse($this->failChallenge(), 'The new login has one failure');
	}

	public function testManyFailuresForOneAccountWithinAnHourFireAcrossLogins(): void {
		for ($i = 1; $i <= 4; $i++) {
			$this->startSession($this->user);
			$this->assertFalse($this->failChallenge('203.0.113.' . $i), 'Failure ' . $i . ' of one per login');
		}
		$this->startSession($this->user);
		$this->assertTrue($this->failChallenge('203.0.113.5'));
		$facts = $this->detectionsOfCheck()[0]->getExplanationData()['facts'];
		$this->assertSame([SecondFactorFailed::RULE_HOUR], $facts['rules']);
		$this->assertSame(5, $facts['hourFailures']);
	}

	public function testTheFirstFailureFromAFlaggedAddressFires(): void {
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp(self::ADDRESS), FlaggedSources::REASON_ATTACK);
		$this->startSession($this->user);
		$this->assertTrue($this->failChallenge());
		$this->assertSame([SecondFactorFailed::RULE_FLAGGED], $this->detectionsOfCheck()[0]->getExplanationData()['facts']['rules']);
	}

	public function testObserveRecordsWhatWouldHaveBeenDoneAndTouchesNothing(): void {
		$this->settings->setMode(SecondFactorFailed::ID, Mode::Observe);
		$pending = $this->startSession($this->user);
		$this->userSession->expects($this->never())->method('logout');
		$this->failChallenge();
		$this->failChallenge();
		$this->assertTrue($this->failChallenge());
		$detection = $this->detectionsOfCheck()[0];
		$this->assertFalse($detection->isEnforced());
		$this->assertTrue($this->tokenExists($pending['id']));
		$this->assertFalse(Server::get(PasswordChangeFlag::class)->isRequired($this->user->getUID()));
		$this->assertSame([], $this->mailed);
		$this->assertSame(0, $this->rows('ids_bans'));
	}

	public function testOffRecordsNothing(): void {
		$this->settings->setMode(SecondFactorFailed::ID, Mode::Off);
		$this->startSession($this->user);
		for ($i = 0; $i < 5; $i++) {
			$this->assertFalse($this->failChallenge());
		}
		$this->assertSame(0, $this->rows('ids_attempts'));
		$this->assertSame(0, $this->rows('ids_detections'));
	}

	private function failChallenge(string $ip = self::ADDRESS): bool {
		return $this->detector->detect($this->user, 'totp', 'TOTP', SourceKey::fromIp($ip), 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0');
	}

	/**
	 * @return list<Detection>
	 */
	private function detectionsOfCheck(): array {
		return $this->detections->findList(new DetectionFilter(checkIds: [SecondFactorFailed::ID]));
	}

	private function rows(string $table): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*'))->from($table);
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}
}
