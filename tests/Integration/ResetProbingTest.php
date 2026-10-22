<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Authentication\TwoFactorAuth\Manager as TwoFactorManager;
use OC\Core\Controller\LostController;
use OC\Security\RateLimiting\Limiter;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\BackgroundJob\Cleanup;
use OCA\IntrusionDetection\Check\Checks\ResetProbing;
use OCA\IntrusionDetection\Check\Checks\ResetProbingDetector;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\ResetSuppressionMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Listener\ResetRequestedListener;
use OCA\IntrusionDetection\Response\ResetMailSuppressor;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Services\IInitialState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Defaults;
use OCP\Encryption\IManager as IEncryptionManager;
use OCP\ICacheFactory;
use OCP\IConfig;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Mail\IEMailTemplate;
use OCP\Mail\IMailer;
use OCP\Mail\IMessage;
use OCP\Security\Events\PasswordResetRequestedEvent;
use OCP\Security\VerificationToken\IVerificationToken;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Password reset abuse (concept section 10.10), driven through core's real
 * LostController, which dispatches PasswordResetRequestedEvent.
 */
#[Group('DB')]
class ResetProbingTest extends RequestEventTestCase {
	/** @var list<string> the addresses reset emails were sent to */
	private array $sentTo = [];
	private BanMapper $bans;

	protected function setUp(): void {
		parent::setUp();
		$this->bans = Server::get(BanMapper::class);
		$this->listen(PasswordResetRequestedEvent::class, new ResetRequestedListener(
			$this->settings,
			$this->addresses,
			Server::get(AttemptRecorder::class),
			Server::get(ResetProbingDetector::class),
			$this->suppressor(),
			Server::get(IUserManager::class),
			$this->request,
			Server::get(LoggerInterface::class),
			Server::get(\OCA\IntrusionDetection\Login\EmailAccounts::class),
		));
	}

	public function testTheAnswerIsTheSameWhetherOrNotTheEmailIsSent(): void {
		$held = $this->user('ids-reset-held', 'held@example.com');
		$sent = $this->user('ids-reset-sent', 'sent@example.com');
		$this->suppressor()->suppress($held->getUID(), time() + 3600);

		$suppressed = $this->askForReset('198.51.100.7', $held->getUID());
		$this->assertSame([], $this->sentTo, 'The held-back account gets no email');
		$delivered = $this->askForReset('198.51.100.8', $sent->getUID());
		$this->assertSame(['sent@example.com'], $this->sentTo);
		$unknown = $this->askForReset('198.51.100.9', 'nobody-' . bin2hex(random_bytes(4)));

		$this->assertSame($this->serialize($delivered), $this->serialize($suppressed), 'Byte for byte the same answer');
		$this->assertSame($this->serialize($delivered), $this->serialize($unknown));

		$this->suppressor()->end($held->getUID());
		$again = $this->askForReset('198.51.100.7', 'held@example.com');
		$this->assertSame(['sent@example.com', 'held@example.com'], $this->sentTo, 'Once the suppression ends, emails are sent again, also by email address');
		$this->assertSame($this->serialize($delivered), $this->serialize($again));
	}

	public function testAFloodHoldsBackFurtherEmailsWithTheSameAnswer(): void {
		$this->settings->setParam(ResetProbing::ID, 'flood_min_requests', 3);
		$victim = $this->user('ids-reset-victim', 'victim@example.com');
		$first = $this->askForReset('203.0.113.1', $victim->getUID());
		$this->askForReset('203.0.113.2', 'victim@example.com');
		$this->assertSame(['victim@example.com', 'victim@example.com'], $this->sentTo);
		$this->assertSame([], $this->detectionsOf(ResetProbing::ID), '2 requests are below the limit of 3');

		$third = $this->askForReset('203.0.113.3', $victim->getUID());
		$fourth = $this->askForReset('203.0.113.4', $victim->getUID());
		$this->assertCount(2, $this->sentTo, 'The request that reaches the limit, and every later one, sends nothing');
		$this->assertSame($this->serialize($first), $this->serialize($third));
		$this->assertSame($this->serialize($first), $this->serialize($fourth));

		$detections = $this->detectionsOf(ResetProbing::ID);
		$this->assertCount(1, $detections, 'The whole flood is one detection');
		$detection = $detections[0];
		$this->assertSame($victim->getUID(), $detection->getUid());
		$this->assertNull($detection->getIp());
		$this->assertSame(2, $detection->getHits());
		$this->assertSame(ResetProbing::RULE_FLOOD, $detection->getExplanationData()['facts']['rule']);
		$this->assertSame(4, $detection->getExplanationData()['facts']['requests']);
		$actions = [];
		foreach ($detection->getActionList() as $action) {
			$actions[$action['type']] = $action;
		}
		$this->assertSame([ResponseType::SuppressResetMail->value, ResponseType::NotifyAdmin->value, ResponseType::NotifyUser->value], array_keys($actions));
		$this->assertTrue($actions[ResponseType::SuppressResetMail->value]['enforced']);
		$this->assertEqualsWithDelta(time() + 3600, $actions[ResponseType::SuppressResetMail->value]['ref']['until'], 5);
		$this->assertArrayHasKey(ResponseType::NotifyUser->value, $actions);
		$this->assertNotSame(ResponseOutcome::NOTE_UNAVAILABLE, $actions[ResponseType::NotifyUser->value]['note'] ?? null);
		$this->assertSame([], $this->bans->findActiveForKeys(['203.0.113.3'], time()), 'A flood from many addresses blocks none of them');

		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$narrative = Server::get(NarrativeBuilder::class)->build($detection, $l);
		$this->assertStringContainsString('someone asked 4 times for password reset emails for the account ' . $victim->getUID() . ', from 4 different addresses', implode(' ', $narrative->happened));
		$this->assertStringContainsString('no password reset emails are sent to ' . $victim->getUID(), implode(' ', $narrative->done));

		$notice = Server::get(ResetProbing::class)->userNotice($detection, $l);
		$this->assertSame('Someone asked for many password reset emails for your account', $notice->subject);
		$this->assertStringContainsString('Someone asked for password reset emails for your account 4 times within 1 hour.', implode(' ', $notice->message));
		$this->assertStringContainsString('Nextcloud stopped sending them until', implode(' ', $notice->message));
		$this->assertStringContainsString('If someone keeps asking, they stay held back until', implode(' ', $notice->message), 'The person learns the latest end');
		$this->assertEqualsWithDelta(time() + ResetMailSuppressor::MAX_SUPPRESSION, $actions[ResponseType::SuppressResetMail->value]['ref']['latest'], 5);
		$this->assertStringContainsString('Your password has not been changed.', implode(' ', $notice->message));
	}

	public function testOnceTheTimeIsUsedUpTheResponseSaysEmailsAreSentAgain(): void {
		$this->settings->setParam(ResetProbing::ID, 'flood_min_requests', 3);
		$victim = $this->user('ids-reset-victim', 'victim@example.com');
		Server::get(ResetSuppressionMapper::class)->suppress($victim->getUID(), null, time() - ResetMailSuppressor::MAX_SUPPRESSION - 60, time() - 60);
		for ($i = 1; $i <= 3; $i++) {
			$this->askForReset('203.0.113.' . $i, $victim->getUID());
		}
		$this->assertCount(3, $this->sentTo, 'Every email is sent');
		$detection = $this->detectionsOf(ResetProbing::ID)[0];
		$action = array_values(array_filter($detection->getActionList(), static fn (array $a): bool => $a['type'] === ResponseType::SuppressResetMail->value))[0];
		$this->assertFalse($action['enforced']);
		$this->assertSame(ResponseOutcome::NOTE_HELD_BACK, $action['note']);
		$narrative = Server::get(NarrativeBuilder::class)->build($detection, Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		$this->assertStringContainsString('are sent again: they were already held back for as long as allowed', implode(' ', $narrative->done));
	}

	public function testEnumerationBlocksTheAddress(): void {
		$existing = $this->user('ids-reset-existing', 'existing@example.com');
		foreach (['nobody-a', 'nobody-b@example.com', $existing->getUID(), 'nobody-c'] as $input) {
			$this->askForReset('198.51.100.7', $input);
		}
		$this->askForReset('198.51.100.7', 'nobody-c');
		$this->assertSame([], $this->detectionsOf(ResetProbing::ID), '4 different inputs are below the limit of 5; a repeated one counts once');

		$this->askForReset('198.51.100.7', 'NOBODY-D');
		$detections = $this->detectionsOf(ResetProbing::ID);
		$this->assertCount(1, $detections);
		$facts = $detections[0]->getExplanationData()['facts'];
		$this->assertSame(ResetProbing::RULE_ENUMERATION, $facts['rule']);
		$this->assertSame(5, $facts['inputs']);
		$this->assertSame(6, $facts['requests']);
		$this->assertSame([$existing->getUID()], $facts['targets'], 'The admin learns which of the tried accounts exist');
		$this->assertSame([ResponseType::Ban->value], array_column($detections[0]->getActionList(), 'type'));
		$this->assertNotSame([], $this->bans->findActiveForKeys(['198.51.100.7'], time()));
		$this->assertStringNotContainsString('nobody', json_encode($detections[0]->getExplanationData(), JSON_THROW_ON_ERROR), 'What was typed is never stored');
	}

	public function testOneAccountAskedRepeatedlyFromOneAddressIsAFloodNotEnumeration(): void {
		$victim = $this->user('ids-reset-victim', 'victim@example.com');
		for ($i = 0; $i < 6; $i++) {
			$this->askForReset('198.51.100.7', $victim->getUID());
		}
		$detections = $this->detectionsOf(ResetProbing::ID);
		$this->assertCount(1, $detections);
		$this->assertSame(ResetProbing::RULE_FLOOD, $detections[0]->getExplanationData()['facts']['rule']);
		$this->assertSame([], $this->bans->findActiveForKeys(['198.51.100.7'], time()));
	}

	public function testInputsResolveToAccountsLikeCoreDoes(): void {
		$byMail = $this->user('ids-reset-mail', 'unique@example.com');
		$disabled = $this->user('ids-reset-disabled', 'disabled@example.com');
		$disabled->setEnabled(false);
		$this->user('ids-reset-twin-a', 'twin@example.com');
		$this->user('ids-reset-twin-b', 'twin@example.com');

		$this->askForReset('198.51.100.7', 'unique@example.com');
		$this->askForReset('198.51.100.8', $disabled->getUID());
		$this->askForReset('198.51.100.9', 'twin@example.com');

		$qb = $this->db->getQueryBuilder();
		$uids = $qb->select('uid')->from(AttemptMapper::TABLE)->orderBy('id')->executeQuery()->fetchFirstColumn();
		$this->assertSame($byMail->getUID(), $uids[0], 'An email address resolves to its account');
		$this->assertNull($uids[1], 'A disabled account gets no email, so it is not flooded');
		// Core's login name mapping picks one of two accounts with the same address; the attempt counts for the account core emails.
		$this->assertSame(['unique@example.com', 'twin@example.com'], $this->sentTo);
		$this->assertSame('twin@example.com', Server::get(IUserManager::class)->get((string)$uids[2])?->getEMailAddress());
	}

	public function testOffSkipsAllWork(): void {
		$this->settings->setMode(ResetProbing::ID, Mode::Off);
		$victim = $this->user('ids-reset-victim', 'victim@example.com');
		$this->suppressor()->suppress($victim->getUID(), time() + 3600);
		for ($i = 0; $i < 6; $i++) {
			$this->askForReset('198.51.100.7', $victim->getUID());
		}
		$this->assertSame(0, $this->rows(AttemptMapper::TABLE));
		$this->assertSame([], $this->detectionsOf(ResetProbing::ID));
		$this->assertCount(5, $this->sentTo, 'Nothing is held back; core\'s own limit of 5 emails per 30 minutes still applies');
	}

	public function testObserveRecordsWhatItWouldHaveDone(): void {
		$this->settings->setGlobal(GlobalSettings::LEARNING_UNTIL, time() + 86400);
		$victim = $this->user('ids-reset-victim', 'victim@example.com');
		for ($i = 1; $i <= 5; $i++) {
			$this->askForReset('203.0.113.' . $i, $victim->getUID());
		}
		$detections = $this->detectionsOf(ResetProbing::ID);
		$this->assertCount(1, $detections);
		$this->assertFalse($detections[0]->isEnforced());
		$this->assertFalse($this->suppressor()->isSuppressed($victim->getUID()));
		$this->assertCount(5, $this->sentTo, 'Every email is still sent');
	}

	public function testSuppressionsEndAndAreCleanedUp(): void {
		$suppressor = $this->suppressor();
		$this->assertSame(time() + 600, $suppressor->suppress('ids-reset-a', time() + 600)['until']);
		$this->assertSame(time() + 600, $suppressor->suppress('ids-reset-a', time() + 300)['until'], 'A shorter suppression does not shorten a running one');
		$this->assertSame(time() + 900, $suppressor->suppress('ids-reset-a', time() + 900)['until'], 'A longer one extends it');
		$suppressor->suppress('ids-reset-b', time() - 1);
		$this->assertFalse($suppressor->isSuppressed('ids-reset-b'));
		$this->assertTrue($suppressor->isSuppressed('ids-reset-a'));

		self::invokePrivate(Server::get(Cleanup::class), 'run', [null]);
		$this->assertNotNull(Server::get(ResetSuppressionMapper::class)->find('ids-reset-b'), 'Kept for its period');
		$this->assertSame(time() + 900, Server::get(ResetSuppressionMapper::class)->expiresAt('ids-reset-a'));
	}

	public function testAnOutsiderCannotHoldBackResetEmailsForever(): void {
		$now = time();
		$suppressor = $this->suppressor(function () use (&$now): int {
			return $now;
		});
		$start = $now;
		$this->assertSame(['until' => $start + 3600, 'latest' => $start + ResetMailSuppressor::MAX_SUPPRESSION], $suppressor->suppress('ids-reset-a', $now + 3600));
		// The flood goes on: every request extends the suppression by an hour, up to the bound.
		for ($hour = 1; $hour <= 30; $hour++) {
			$now = $start + $hour * 3600;
			$result = $suppressor->suppress('ids-reset-a', $now + 3600);
		}
		$this->assertSame($start + ResetMailSuppressor::MAX_SUPPRESSION, $result['latest']);
		$this->assertLessThan($now, $result['until'], 'After a day emails are sent again');
		$this->assertFalse($suppressor->isSuppressed('ids-reset-a'));

		$now = $start + ResetMailSuppressor::PERIOD - 60;
		$this->assertFalse($suppressor->isSuppressed('ids-reset-a'));
		$this->assertLessThan($now, $suppressor->suppress('ids-reset-a', $now + 3600)['until'], 'Not again within the period');

		$now = $start + ResetMailSuppressor::PERIOD + 1;
		$this->assertSame($now + 3600, $suppressor->suppress('ids-reset-a', $now + 3600)['until'], 'A new period may start');
	}

	public function testTheCleanupKeepsARowForItsWholePeriod(): void {
		$mapper = Server::get(ResetSuppressionMapper::class);
		$mapper->suppress('ids-reset-old', null, time() - ResetMailSuppressor::PERIOD - 10, time() - 3600);
		$mapper->suppress('ids-reset-recent', null, time() - 7200, time() - 3600);
		self::invokePrivate(Server::get(Cleanup::class), 'run', [null]);
		$this->assertNull($mapper->find('ids-reset-old'));
		$this->assertNotNull($mapper->find('ids-reset-recent'));
	}

	private function askForReset(string $ip, string $input): JSONResponse {
		$this->remoteAddress = $ip;
		return $this->lostController()->email($input);
	}

	/**
	 * Core's controller with the real event dispatcher, user lookup, rate
	 * limiter and email template; only the mail server is replaced.
	 */
	private function lostController(): LostController {
		$real = Server::get(IMailer::class);
		$mailer = $this->createMock(IMailer::class);
		$mailer->method('createEMailTemplate')->willReturnCallback(static fn (string $id, array $data = []): IEMailTemplate => $real->createEMailTemplate($id, $data));
		$mailer->method('createMessage')->willReturnCallback(static fn (): IMessage => $real->createMessage());
		$mailer->method('send')->willReturnCallback(function (IMessage $message): array {
			$this->sentTo[] = (string)array_key_first($message->getTo());
			return [];
		});
		return new LostController(
			'core',
			$this->request,
			Server::get(IURLGenerator::class),
			Server::get(IUserManager::class),
			Server::get(Defaults::class),
			Server::get(IFactory::class)->get('core', 'en'),
			Server::get(IConfig::class),
			'no-reply@example.com',
			Server::get(IEncryptionManager::class),
			$mailer,
			Server::get(LoggerInterface::class),
			$this->createMock(TwoFactorManager::class),
			$this->createMock(IInitialState::class),
			Server::get(IVerificationToken::class),
			Server::get(\OCP\EventDispatcher\IEventDispatcher::class),
			Server::get(Limiter::class),
		);
	}

	/**
	 * Everything the client receives: status, headers, body, and whether the
	 * response is throttled.
	 */
	private function serialize(JSONResponse $response): string {
		return json_encode([$response->getStatus(), $response->getHeaders(), $response->render(), $response->isThrottled(), $response->getThrottleMetadata()], JSON_THROW_ON_ERROR);
	}

	/**
	 * @param ?\Closure(): int $clock
	 */
	private function suppressor(?\Closure $clock = null): ResetMailSuppressor {
		// Without a cache, so that suppressions set by one test are seen at once and not by the next.
		$cacheFactory = $this->createMock(ICacheFactory::class);
		$time = Server::get(ITimeFactory::class);
		if ($clock !== null) {
			$time = $this->createMock(ITimeFactory::class);
			$time->method('getTime')->willReturnCallback($clock);
		}
		return new ResetMailSuppressor(Server::get(ResetSuppressionMapper::class), $time, $cacheFactory);
	}

	protected function user(string $prefix, ?string $email = null): IUser {
		return parent::user($prefix, $email);
	}
}
