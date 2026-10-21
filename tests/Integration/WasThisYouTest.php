<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack;
use OCA\IntrusionDetection\Check\Checks\BreachedPassword;
use OCA\IntrusionDetection\Check\Checks\LoginFlowMismatch;
use OCA\IntrusionDetection\Check\Checks\SecondFactorFailed;
use OCA\IntrusionDetection\Check\Checks\StepUpUnconfirmed;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;
use OCA\IntrusionDetection\Check\Checks\UserDenied;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\LoginDetections;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Controller\PersonalApiController;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\KnownDeviceMapper;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Event\WasThisYouAnsweredEvent;
use OCA\IntrusionDetection\Guide\SecureAccountGuide;
use OCA\IntrusionDetection\Guide\SecureAccountOverview;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Personal\LogOutElsewhere;
use OCA\IntrusionDetection\Personal\PersonalActivity;
use OCA\IntrusionDetection\Personal\PersonalOverview;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\PasswordChangeFlag;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCA\IntrusionDetection\WasThisYou\AnswerException;
use OCA\IntrusionDetection\WasThisYou\PersonalDetections;
use OCA\IntrusionDetection\WasThisYou\Questions;
use OCA\IntrusionDetection\WasThisYou\WasThisYouService;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Token\IToken;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use OCP\Notification\IManager as INotificationManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * "Was this you?" (concept section 11.8): who may answer, from where, and
 * what each answer does.
 */
#[Group('DB')]
class WasThisYouTest extends StepUpTestCase {
	private const ATTACKER = '203.0.113.66';

	private IUser $alice;
	/** @var list<CriticalActionPerformedEvent> */
	private array $audited = [];
	/** @var list<WasThisYouAnsweredEvent> */
	private array $answered = [];
	private \Closure $auditListener;
	private \Closure $answerListener;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-wty', 'alice@example.com');
		CapturingNotificationApp::$processed = [];
		$this->auditListener = function (CriticalActionPerformedEvent $e): void {
			$this->audited[] = $e;
		};
		$this->answerListener = function (WasThisYouAnsweredEvent $e): void {
			$this->answered[] = $e;
		};
		Server::get(IEventDispatcher::class)->addListener(CriticalActionPerformedEvent::class, $this->auditListener);
		Server::get(IEventDispatcher::class)->addListener(WasThisYouAnsweredEvent::class, $this->answerListener);
	}

	protected function tearDown(): void {
		Server::get(IEventDispatcher::class)->removeListener(CriticalActionPerformedEvent::class, $this->auditListener);
		Server::get(IEventDispatcher::class)->removeListener(WasThisYouAnsweredEvent::class, $this->answerListener);
		parent::tearDown();
	}

	public function testOnlyTheUsersOwnAskingDetectionsCanBeAnswered(): void {
		$bob = $this->user('ids-wty-bob', 'bob@example.com');
		$hers = $this->detection(SecondFactorFailed::ID, $this->alice);
		$this->startSession($bob);
		foreach (['deny', 'confirm'] as $answer) {
			$this->assertAnswerFails(AnswerException::NOT_FOUND, fn () => $this->answers()->{$answer}($bob, $hers->getId()), 'Another account\'s detection looks like a missing one');
			$this->assertAnswerFails(AnswerException::NOT_FOUND, fn () => $this->answers()->{$answer}($bob, 999999999));
		}
		$this->startSession($this->alice);
		$breach = $this->detection(BreachedPassword::ID, $this->alice);
		$this->assertAnswerFails(AnswerException::NOT_ASKED, fn () => $this->answers()->deny($this->alice, $breach->getId()), 'A fact about the password, not an event to recognise');
		$this->assertNull(Server::get(DetectionMapper::class)->findById($hers->getId())->getUserVerdict());
	}

	public function testNoEndsTheSessionAndTheAppPasswordsBlocksAndTellsTheAdministrators(): void {
		$other = $this->token($this->alice, IToken::TEMPORARY_TOKEN, 'The real Alice on her laptop');
		$suspicious = $this->token($this->alice, IToken::TEMPORARY_TOKEN, 'The session the detection is about');
		$appPassword = $this->token($this->alice, IToken::PERMANENT_TOKEN, 'Created in that session');
		Server::get(TokenOriginMapper::class)->record($appPassword['id'], $this->alice->getUID(), self::ATTACKER, $suspicious['id'], time());
		Server::get(TrustedNetworks::class)->trust($this->alice->getUID(), SourceKey::fromIp(self::ATTACKER));
		$detection = $this->detection(SecondFactorFailed::ID, $this->alice, ['sessionTokenId' => $suspicious['id']]);
		$this->session->id = $other['secret'];
		$this->sessionUser = $this->alice;
		$this->prove($this->alice);

		$this->answers()->deny($this->alice, $detection->getId());

		$this->assertFalse($this->tokenExists($suspicious['id']), 'The session is ended');
		$this->assertFalse($this->tokenExists($appPassword['id']), 'And the app password made in it');
		$this->assertTrue($this->tokenExists($other['id']), 'Other devices keep working');
		$this->assertTrue(Server::get(PasswordChangeFlag::class)->isRequired($this->alice->getUID()), 'The password was involved');
		$bans = Server::get(BanMapper::class)->findActiveForKeys([SourceKey::fromIp(self::ATTACKER)->ipKey], time());
		$this->assertCount(1, $bans);
		$this->assertSame(2, $bans[0]->getLevel(), 'Blocked at the second level');
		$this->assertSame(FlaggedSources::REASON_USER_DENIED, Server::get(FlaggedSources::class)->sourceFlag(SourceKey::fromIp('203.0.113.1')), 'Its network is marked');
		$this->assertFalse(Server::get(TrustedNetworks::class)->isTrusted($this->alice->getUID(), SourceKey::fromIp(self::ATTACKER)), 'No longer trusted');

		$stored = Server::get(DetectionMapper::class)->findById($detection->getId());
		$this->assertSame(Detection::VERDICT_DENIED, $stored->getUserVerdict());
		$this->assertNotNull($stored->getVerdictAt());
		$denial = $this->detectionsOf(UserDenied::ID)[0];
		$this->assertSame(Severity::High->value, $denial->getSeverity());
		$this->assertSame($detection->getId(), $denial->getExplanationData()['facts']['detection']);
		$this->assertNotEmpty($this->notificationsFor('admin', AdminAlerts::SUBJECT), 'The administrators are told');
		$this->assertCount(1, $this->answered);
		$this->assertTrue($this->answered[0]->isDenied());
		$this->assertTrue($this->wasAudited('"No, it was not me"'));
		$this->assertSame([[$this->alice->getUID(), UserAlerts::OBJECT_TYPE, (string)$detection->getId()]], array_values(array_unique(array_map(
			static fn ($n): array => [$n->getUser(), $n->getObjectType(), $n->getObjectId()],
			array_filter(CapturingNotificationApp::$processed, static fn ($n): bool => $n->getObjectType() === UserAlerts::OBJECT_TYPE),
		), SORT_REGULAR)), 'The notification with the question goes away');
	}

	public function testNoAboutAConnectedDeviceRevokesItWithoutANewPassword(): void {
		$this->provenSession($this->alice);
		$device = $this->token($this->alice, IToken::PERMANENT_TOKEN, 'Phished desktop app');
		$detection = $this->detection(LoginFlowMismatch::ID, $this->alice, ['tokenId' => $device['id']], Severity::Medium);
		$this->answers()->deny($this->alice, $detection->getId());
		$this->assertFalse($this->tokenExists($device['id']));
		$this->assertFalse(Server::get(PasswordChangeFlag::class)->isRequired($this->alice->getUID()), 'The password was not involved');
	}

	public function testNoFromTheEventsOwnAddressDoesNotLockOutTheOneWhoAnswers(): void {
		$this->remoteAddress = self::ATTACKER;
		$this->provenSession($this->alice);
		$detection = $this->detection(SecondFactorFailed::ID, $this->alice);
		$this->answers()->deny($this->alice, $detection->getId());
		$this->assertSame([], Server::get(BanMapper::class)->findActiveForKeys([SourceKey::fromIp(self::ATTACKER)->ipKey], time()));
		$this->assertTrue(Server::get(PasswordChangeFlag::class)->isRequired($this->alice->getUID()), 'Everything else still happens');
		$this->assertSame(FlaggedSources::REASON_USER_DENIED, Server::get(FlaggedSources::class)->sourceFlag(SourceKey::fromIp(self::ATTACKER)));
	}

	public function testNoActsEvenWhileLearning(): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);
		$this->provenSession($this->alice);
		$detection = $this->detection(SecondFactorFailed::ID, $this->alice);
		$this->answers()->deny($this->alice, $detection->getId());
		$this->assertNotSame([], Server::get(BanMapper::class)->findActiveForKeys([SourceKey::fromIp(self::ATTACKER)->ipKey], time()), 'It is the account holder\'s decision');
	}

	public function testEachDetectionTakesOneAnswer(): void {
		$this->provenSession($this->alice);
		$detection = $this->detection(SecondFactorFailed::ID, $this->alice);
		$this->answers()->deny($this->alice, $detection->getId());
		$this->assertAnswerFails(AnswerException::ANSWERED, fn () => $this->answers()->deny($this->alice, $detection->getId()));
		$this->provenSession($this->alice);
		$this->assertAnswerFails(AnswerException::ANSWERED, fn () => $this->answers()->confirm($this->alice, $detection->getId()));
		$this->assertCount(1, $this->detectionsOf(UserDenied::ID));
		$this->assertFalse(Server::get(DetectionMapper::class)->setVerdict($detection->getId(), $this->alice->getUID(), Detection::VERDICT_CONFIRMED, time()), 'Also when two answers race');
	}

	public function testYesIsRefusedFromTheSessionTheDetectionIsAbout(): void {
		$suspicious = $this->provenSession($this->alice);
		$byFact = $this->detection(SecondFactorFailed::ID, $this->alice, ['sessionTokenId' => $suspicious['id']]);
		$byLink = $this->detection(StepUpUnconfirmed::ID, $this->alice, [LoginDetections::FACT => [12345, $suspicious['id']], 'policies' => ['flagged_source']]);
		$byToken = $this->detection(LoginFlowMismatch::ID, $this->alice, ['tokenId' => $suspicious['id']], Severity::Medium);
		foreach ([$byFact, $byLink, $byToken] as $detection) {
			$this->assertAnswerFails(AnswerException::SESSION_NOT_ALLOWED, fn () => $this->answers()->confirm($this->alice, $detection->getId()), $detection->getCheckId());
			$this->assertNull(Server::get(DetectionMapper::class)->findById($detection->getId())->getUserVerdict());
		}
	}

	public function testYesIsRefusedFromSessionsThatCannotVouch(): void {
		$detection = $this->detection(SecondFactorFailed::ID, $this->alice);
		$this->startSession($this->alice);
		$this->state->set(SessionState::CONFIRMATION, ['uid' => $this->alice->getUID(), 'by' => 'none', 'policies' => [StepUpPolicy::FlaggedSource->value], 'at' => time()]);
		$this->assertAnswerFails(AnswerException::SESSION_NOT_ALLOWED, fn () => $this->answers()->confirm($this->alice, $detection->getId()), 'A login nothing confirmed');

		$this->startSession($this->alice);
		$this->session->set('app_password', 'xxx');
		$this->assertAnswerFails(AnswerException::SESSION_NOT_ALLOWED, fn () => $this->answers()->confirm($this->alice, $detection->getId()), 'An app password session');

		$this->session->clear();
		$this->session->id = 'no-token-' . bin2hex(random_bytes(8));
		$this->prove($this->alice);
		$this->assertAnswerFails(AnswerException::SESSION_NOT_ALLOWED, fn () => $this->answers()->confirm($this->alice, $detection->getId()), 'A session whose token is unknown');

		$this->session->clear();
		$this->startSession($this->alice);
		$this->assertAnswerFails(AnswerException::SESSION_NOT_ALLOWED, fn () => $this->answers()->confirm($this->alice, $detection->getId()), 'A login that proved only the password');
		$this->prove($this->alice);
		$this->answers()->confirm($this->alice, $detection->getId());
		$this->assertSame(Detection::VERDICT_CONFIRMED, Server::get(DetectionMapper::class)->findById($detection->getId())->getUserVerdict(), 'A login that proved its second factor');
	}

	public function testNoIsRefusedFromUnconfirmedSessions(): void {
		$detection = $this->detection(SecondFactorFailed::ID, $this->alice);
		$this->startSession($this->alice);
		$this->state->set(SessionState::CONFIRMATION, ['uid' => $this->alice->getUID(), 'by' => 'none', 'policies' => [StepUpPolicy::FlaggedSource->value], 'at' => time()]);
		$this->assertAnswerFails(AnswerException::SESSION_NOT_ALLOWED, fn () => $this->answers()->deny($this->alice, $detection->getId()), 'A login let in without a confirmation');

		$this->session->clear();
		$this->startSession($this->alice);
		$this->state->set(SessionState::STEP_UP, (new StepUpState($this->alice->getUID(), StepUpState::PENDING, ['flagged_source'], time(), time() + 900))->toArray());
		$this->assertAnswerFails(AnswerException::SESSION_NOT_ALLOWED, fn () => $this->answers()->deny($this->alice, $detection->getId()), 'A login that waits for its confirmation');

		$this->session->clear();
		$this->startSession($this->alice);
		$this->session->set('app_password', 'xxx');
		$this->assertAnswerFails(AnswerException::SESSION_NOT_ALLOWED, fn () => $this->answers()->deny($this->alice, $detection->getId()), 'An app password');
		$this->assertNull(Server::get(DetectionMapper::class)->findById($detection->getId())->getUserVerdict());
		$this->assertSame([], $this->detectionsOf(UserDenied::ID));
	}

	public function testNoFromALoginThatProvedOnlyThePasswordOnlyTellsTheAdministrators(): void {
		$suspicious = $this->token($this->alice, IToken::TEMPORARY_TOKEN, 'The owner\'s session');
		Server::get(TrustedNetworks::class)->trust($this->alice->getUID(), SourceKey::fromIp(self::ATTACKER));
		$detection = $this->detection(SecondFactorFailed::ID, $this->alice, ['sessionTokenId' => $suspicious['id']]);
		$this->startSession($this->alice);

		Server::get(KnownDeviceMapper::class)->insert($this->alice->getUID(), str_repeat('ab', 32), 'firefox', 'linux', 'Firefox on Linux', null, time());

		$answered = $this->answers()->deny($this->alice, $detection->getId());

		$this->assertNull($answered->getUserVerdict());
		$this->assertNull(Server::get(DetectionMapper::class)->findById($detection->getId())->getUserVerdict(), 'The question stays open for the account holder');
		$this->assertTrue(Server::get(Questions::class)->asks($detection));
		$this->assertSame([], array_filter(CapturingNotificationApp::$processed, static fn ($n): bool => $n->getObjectType() === UserAlerts::OBJECT_TYPE), 'Its notification stays');
		$this->assertSame([], $this->answered, 'Not an answer: the remembered devices and the guide are left alone');
		$this->assertCount(1, Server::get(KnownDeviceMapper::class)->forUser($this->alice->getUID(), 0, 10), 'The remembered devices are kept');
		$this->assertTrue($this->wasAudited('proved only the password'));
		$denial = $this->detectionsOf(UserDenied::ID)[0];
		$this->assertTrue($denial->getExplanationData()['facts']['weakSession']);
		$this->assertNotEmpty($this->notificationsFor('admin', AdminAlerts::SUBJECT), 'The administrators are told');
		$this->assertTrue($this->tokenExists($suspicious['id']), 'No session is ended');
		$this->assertSame([], Server::get(BanMapper::class)->findActiveForKeys([SourceKey::fromIp(self::ATTACKER)->ipKey], time()), 'Nothing is blocked');
		$this->assertNull(Server::get(FlaggedSources::class)->sourceFlag(SourceKey::fromIp(self::ATTACKER)), 'Nothing is marked');
		$this->assertFalse(Server::get(PasswordChangeFlag::class)->isRequired($this->alice->getUID()), 'No new password: whoever answered may know it');
		$this->assertTrue(Server::get(TrustedNetworks::class)->isTrusted($this->alice->getUID(), SourceKey::fromIp(self::ATTACKER)));
	}

	public function testAProvenAnswerAfterAWeakNoDecides(): void {
		$suspicious = $this->token($this->alice, IToken::TEMPORARY_TOKEN, 'The attacker\'s session');
		$detection = $this->detection(SecondFactorFailed::ID, $this->alice, ['sessionTokenId' => $suspicious['id']]);
		$this->startSession($this->alice);
		$this->answers()->deny($this->alice, $detection->getId());
		$this->answers()->deny($this->alice, $detection->getId());
		$this->assertNull(Server::get(DetectionMapper::class)->findById($detection->getId())->getUserVerdict(), 'A weak "No" again changes nothing');
		$this->assertTrue($this->tokenExists($suspicious['id']));

		$this->session->clear();
		$this->provenSession($this->alice);
		$this->answers()->deny($this->alice, $detection->getId());
		$this->assertSame(Detection::VERDICT_DENIED, Server::get(DetectionMapper::class)->findById($detection->getId())->getUserVerdict(), 'The proven answer decides');
		$this->assertFalse($this->tokenExists($suspicious['id']), 'Now the session ends');
		$this->assertCount(1, $this->answered);
		$this->assertTrue($this->answered[0]->isDenied());
		$this->assertAnswerFails(AnswerException::ANSWERED, fn () => $this->answers()->deny($this->alice, $detection->getId()));

		$other = $this->detection(SecondFactorFailed::ID, $this->alice);
		$this->session->clear();
		$this->startSession($this->alice);
		$this->answers()->deny($this->alice, $other->getId());
		$this->session->clear();
		$this->provenSession($this->alice);
		$this->answers()->confirm($this->alice, $other->getId());
		$this->assertSame(Detection::VERDICT_CONFIRMED, Server::get(DetectionMapper::class)->findById($other->getId())->getUserVerdict(), 'Or the proven "Yes"');
	}

	public function testAnswersAboutATokenUsedFromTwoPlacesNeverBlockMarkOrTrustANetwork(): void {
		$this->provenSession($this->alice);
		$facts = ['ip1' => '198.51.100.30', 'net1' => '198.51.100.0/24', 'ip2' => self::ATTACKER, 'net2' => '203.0.113.0/24', 'kind' => 'password', 'scheme' => 'basic'];
		$password = $this->detection(TokenConcurrentUse::ID, $this->alice, $facts);
		$this->assertTrue(Server::get(Questions::class)->asks($password));
		$this->assertTrue(Server::get(Questions::class)->involvesPassword($password), 'The password was sent from both places');
		$this->answers()->deny($this->alice, $password->getId());
		$this->assertTrue(Server::get(PasswordChangeFlag::class)->isRequired($this->alice->getUID()));
		$this->assertSame([], Server::get(BanMapper::class)->findActiveForKeys([SourceKey::fromIp(self::ATTACKER)->ipKey, SourceKey::fromIp('198.51.100.30')->ipKey], time()), 'Either address may be the account holder\'s');
		$this->assertNull(Server::get(FlaggedSources::class)->sourceFlag(SourceKey::fromIp(self::ATTACKER)));
		$this->assertNull(Server::get(FlaggedSources::class)->sourceFlag(SourceKey::fromIp('198.51.100.30')));

		$appPassword = $this->token($this->alice, IToken::PERMANENT_TOKEN, 'Phone');
		$token = $this->detection(TokenConcurrentUse::ID, $this->alice, ['kind' => 'app_password', 'tokenId' => $appPassword['id']] + $facts);
		$this->assertFalse(Server::get(Questions::class)->involvesPassword($token));
		$this->answers()->deny($this->alice, $token->getId());
		$this->assertFalse($this->tokenExists($appPassword['id']), 'The app password is revoked');

		$yes = $this->detection(TokenConcurrentUse::ID, $this->alice, ['kind' => 'session'] + $facts);
		$this->answers()->confirm($this->alice, $yes->getId());
		$this->assertSame([], Server::get(TrustedNetworks::class)->forUser($this->alice->getUID()), 'No network is trusted');
	}

	public function testAnAccountUnderAttackDoesNotAsk(): void {
		$detection = $this->detection(AccountUnderAttack::ID, $this->alice);
		$this->assertFalse(Server::get(Questions::class)->asks($detection), 'Nobody got in: there is nothing to recognise');
	}

	public function testYesTrustsTheNetworkSoThatFlaggedSourcesNoLongerAsk(): void {
		$detection = $this->detection(SecondFactorFailed::ID, $this->alice);
		$this->provenSession($this->alice);
		$this->answers()->confirm($this->alice, $detection->getId());

		$this->assertSame(Detection::VERDICT_CONFIRMED, Server::get(DetectionMapper::class)->findById($detection->getId())->getUserVerdict());
		$trusted = Server::get(TrustedNetworks::class)->forUser($this->alice->getUID());
		$this->assertCount(1, $trusted);
		$this->assertSame('203.0.113.0/24', $trusted[0]['network']);
		$this->assertSame($detection->getId(), $trusted[0]['detectionId']);
		$this->assertTrue($this->wasAudited('"Yes, it was me"'));
		$this->assertFalse($this->answered[0]->isDenied());

		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp(self::ATTACKER), FlaggedSources::REASON_ATTACK);
		$this->remoteAddress = self::ATTACKER;
		$this->session->clear();
		$this->session->id = null;
		$this->login($this->alice);
		$this->assertNull($this->stepUp(), 'A login from the trusted network is not asked again');
	}

	public function testTheNotificationOffersBothAnswersUntilOneIsGiven(): void {
		$detection = $this->detection(SecondFactorFailed::ID, $this->alice);
		$plain = $this->detection(BreachedPassword::ID, $this->alice);
		$prepare = function (Detection $d): \OCP\Notification\INotification {
			$n = Server::get(INotificationManager::class)->createNotification();
			$n->setApp(Application::APP_ID)->setUser($this->alice->getUID())->setDateTime(new \DateTime())
				->setObject(UserAlerts::OBJECT_TYPE, (string)$d->getId())->setSubject(UserAlerts::SUBJECT, ['detection' => $d->getId()]);
			return Server::get(Notifier::class)->prepare($n, 'en');
		};

		$actions = $prepare($detection)->getParsedActions();
		$this->assertCount(2, $actions);
		$this->assertSame(['No, it was not me', 'Yes, it was me'], array_map(static fn ($a): string => $a->getParsedLabel(), $actions));
		$this->assertSame('POST', $actions[0]->getRequestType());
		$this->assertMatchesRegularExpression('#/ocs/v2\.php/apps/intrusion_detection/api/v1/personal/detections/' . $detection->getId() . '/deny$#', $actions[0]->getLink(), 'Only the detection id');
		$this->assertSame('WEB', $actions[1]->getRequestType(), '"Yes" needs the password, which the notification cannot ask');
		$this->assertStringContainsString('/settings/user/security', $actions[1]->getLink());
		$this->assertSame([], $prepare($plain)->getParsedActions());
		$this->assertStringContainsString('Was this you?', $prepare($detection)->getParsedMessage());

		$this->provenSession($this->alice);
		$this->answers()->confirm($this->alice, $detection->getId());
		$this->assertSame([], $prepare($detection)->getParsedActions(), 'Answered');
	}

	public function testThePersonalApiListsOnlyTheUsersOwnEventsInPlainWords(): void {
		$bob = $this->user('ids-wty-bob2', 'bob@example.com');
		$mine = $this->detection(SecondFactorFailed::ID, $this->alice, ['loginFailures' => 3, 'hourFailures' => 3, 'providerName' => 'TOTP']);
		$this->detection(SecondFactorFailed::ID, $bob);
		$this->provenSession($this->alice);

		$response = $this->controller()->detections();
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$list = $response->getData();
		$this->assertCount(1, $list);
		$this->assertSame($mine->getId(), $list[0]['id']);
		$this->assertSame(['id', 'check', 'severity', 'enforced', 'createdAt', 'lastSeenAt', 'hits', 'subject', 'happened', 'when', 'done', 'advice', 'address', 'asks', 'verdict', 'verdictAt', 'canConfirm'], array_keys($list[0]), 'No explanation, thresholds or actions');
		$this->assertTrue($list[0]['asks']);
		$this->assertTrue($list[0]['canConfirm']);
		$this->assertStringNotContainsString('limit', strtolower(json_encode($list, JSON_THROW_ON_ERROR)), 'Users never see thresholds');
		$this->assertStringNotContainsString($bob->getUID(), json_encode($list, JSON_THROW_ON_ERROR));
	}

	public function testThePersonalApiAnswersAndManagesTrustedNetworks(): void {
		$bob = $this->user('ids-wty-bob3', 'bob@example.com');
		$detection = $this->detection(SecondFactorFailed::ID, $this->alice);
		$this->provenSession($this->alice);
		$this->assertSame(Http::STATUS_NOT_FOUND, $this->controller()->deny(999999999)->getStatus());
		$response = $this->controller()->confirm($detection->getId());
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame('confirmed', $response->getData()['verdict']);
		$this->assertSame(Http::STATUS_CONFLICT, $this->controller()->deny($detection->getId())->getStatus());

		$networks = $this->controller()->trustedNetworks()->getData();
		$this->assertCount(1, $networks);
		Server::get(TrustedNetworks::class)->trust($bob->getUID(), SourceKey::fromIp('192.0.2.1'));
		$bobs = Server::get(TrustedNetworks::class)->forUser($bob->getUID())[0]['id'];
		$this->assertSame(Http::STATUS_NOT_FOUND, $this->controller()->removeTrustedNetwork($bobs)->getStatus(), 'Never another account\'s');
		$this->assertCount(1, Server::get(TrustedNetworks::class)->forUser($bob->getUID()));
		$this->assertSame(['removed' => $networks[0]['id']], $this->controller()->removeTrustedNetwork($networks[0]['id'])->getData());
		$this->assertSame([], $this->controller()->trustedNetworks()->getData());

		$suspicious = $this->provenSession($this->alice);
		$own = $this->detection(SecondFactorFailed::ID, $this->alice, ['sessionTokenId' => $suspicious['id']]);
		$refused = $this->controller()->confirm($own->getId());
		$this->assertSame(Http::STATUS_FORBIDDEN, $refused->getStatus());
		$this->assertSame(AnswerException::SESSION_NOT_ALLOWED, $refused->getData()['reason']);
	}

	public function testTheEndpointsAreProtected(): void {
		$class = new \ReflectionClass(PersonalApiController::class);
		foreach (['detections', 'deny', 'confirm', 'trustedNetworks', 'removeTrustedNetwork'] as $name) {
			$method = $class->getMethod($name);
			$this->assertNotSame([], $method->getAttributes(NoAdminRequired::class), $name);
			$this->assertSame([], $method->getAttributes(NoCSRFRequired::class), $name);
		}
		foreach (['deny', 'confirm', 'removeTrustedNetwork'] as $name) {
			$this->assertNotSame([], $class->getMethod($name)->getAttributes(UserRateLimit::class), $name);
		}
		$this->assertNotSame([], $class->getMethod('confirm')->getAttributes(PasswordConfirmationRequired::class), '"Yes" needs the password');
		$this->assertSame([], $class->getMethod('deny')->getAttributes(PasswordConfirmationRequired::class), '"No" needs nothing: it only locks someone out');
	}

	/**
	 * @param array<string, mixed> $facts
	 */
	private function detection(string $checkId, IUser $user, array $facts = [], ?Severity $severity = null): Detection {
		if ($checkId === BreachedPassword::ID) {
			// Off by default.
			$this->appConfig->setValueString(Application::APP_ID, Keys::mode(BreachedPassword::ID), Mode::Protect->value);
		}
		$detection = $this->engine()->handle(new DetectionDraft(
			checkId: $checkId,
			source: SourceKey::fromIp(self::ATTACKER),
			uid: $user->getUID(),
			facts: $facts,
			severity: $severity,
			userAgent: 'Mozilla/5.0',
		), []);
		$this->assertNotNull($detection);
		return $detection;
	}

	/**
	 * A session whose login passed the second factor.
	 *
	 * @return array{id: int, secret: string}
	 */
	private function provenSession(IUser $user): array {
		$token = $this->startSession($user);
		$this->prove($user);
		return $token;
	}

	private function prove(IUser $user): void {
		$this->sessionConfirmation()->proved($user->getUID(), IConfirmationMethod::SECOND_FACTOR);
	}

	private function answers(): WasThisYouService {
		return new WasThisYouService(
			Server::get(DetectionMapper::class),
			Server::get(Questions::class),
			$this->engine(),
			Server::get(UserDenied::class),
			$this->settings,
			Server::get(FlaggedSources::class),
			Server::get(TrustedNetworks::class),
			$this->sessionKiller(),
			$this->currentSession,
			$this->addresses(),
			$this->sessionConfirmation(),
			Server::get(INotificationManager::class),
			Server::get(IEventDispatcher::class),
			Server::get(AuditLogger::class),
			Server::get(ITimeFactory::class),
		);
	}

	private function controller(): PersonalApiController {
		$service = $this->answers();
		return new PersonalApiController(
			$this->request,
			$this->userSession,
			new PersonalDetections(Server::get(DetectionMapper::class), Server::get(UserMessages::class), Server::get(Questions::class), $service, $this->settings, Server::get(ITimeFactory::class)),
			$service,
			Server::get(TrustedNetworks::class),
			Server::get(IFactory::class)->get(Application::APP_ID, 'en'),
			Server::get(KnownDevices::class),
			Server::get(LoginHistoryMapper::class),
			$this->currentSession,
			Server::get(SecureAccountGuide::class),
			Server::get(SecureAccountOverview::class),
			Server::get(SecurityChangeMapper::class),
			$this->settings,
			Server::get(ITimeFactory::class),
			Server::get(PersonalOverview::class),
			Server::get(LogOutElsewhere::class),
			Server::get(PersonalActivity::class),
		);
	}

	private function assertAnswerFails(string $reason, \Closure $answer, string $message = ''): void {
		try {
			$answer();
			$this->fail('The answer must be refused: ' . $message);
		} catch (AnswerException $e) {
			$this->assertSame($reason, $e->reason, $message);
		}
	}

	private function wasAudited(string $text): bool {
		foreach ($this->audited as $event) {
			if (str_contains($event->getLogMessage(), $text)) {
				return true;
			}
		}
		return false;
	}
}
