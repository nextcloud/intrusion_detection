<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\Files_Sharing\Controller\ShareController;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforceDetector;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Controller\ShareAlertController;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Listener\ShareAccessFailedListener;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\MailContent;
use OCA\IntrusionDetection\Notification\Mails;
use OCA\IntrusionDetection\Notification\ShareOwnerAlerts;
use OCA\IntrusionDetection\Notification\ShareOwnerNotifier;
use OCA\IntrusionDetection\Share\ShareLinks;
use OCP\AppFramework\Http;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Notification\AlreadyProcessedException;
use OCP\Notification\IManager as INotificationManager;
use OCP\Notification\INotification;
use OCP\Server;
use OCP\Share\Events\ShareLinkAccessFailedEvent;
use OCP\Share\Exceptions\ShareNotFound;
use OCP\Share\IManager as IShareManager;
use OCP\Share\IShare;
use PHPUnit\Framework\Attributes\Group;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Share link attacks (concept section 10.9), driven through the real share
 * page controller, which dispatches ShareLinkAccessFailedEvent.
 */
#[Group('DB')]
class ShareBruteforceTest extends RequestEventTestCase {
	private const SHARE_PASSWORD = 'Correct-Horse-Battery-Staple-1';

	private BanMapper $bans;
	private AttemptMapper $attempts;

	protected function setUp(): void {
		parent::setUp();
		$this->bans = Server::get(BanMapper::class);
		$this->attempts = Server::get(AttemptMapper::class);
		$this->listen(ShareLinkAccessFailedEvent::class, new ShareAccessFailedListener(
			$this->settings,
			$this->addresses,
			Server::get(AttemptRecorder::class),
			Server::get(ShareBruteforceDetector::class),
			$this->request,
			Server::get(IUserSession::class),
			Server::get(LoggerInterface::class),
		));
	}

	public function testOneOrTwoOutdatedLinksNeverFire(): void {
		$this->settings->setParam(ShareBruteforce::ID, 'token_min', 3);
		for ($i = 0; $i < 5; $i++) {
			$this->openUnknownLink('198.51.100.7', 'outdatedLinkAaaa');
			$this->openUnknownLink('198.51.100.7', 'outdatedLinkBbbb');
		}
		$this->assertSame(10, $this->rows(AttemptMapper::TABLE), 'Every failed access is recorded');
		$this->assertSame([], $this->detectionsOf(ShareBruteforce::ID), 'Two outdated links are never an attack, even at the lowest limit');

		$this->openUnknownLink('198.51.100.7', 'outdatedLinkCccc');
		$this->assertCount(1, $this->detectionsOf(ShareBruteforce::ID), 'A third different link reaches the lowest limit');
	}

	public function testTokensThatDifferOnlyInCaseAreDifferentGuesses(): void {
		$this->settings->setParam(ShareBruteforce::ID, 'token_min', 3);
		foreach (['caseToken', 'CaseToken', 'CASETOKEN'] as $token) {
			$this->openUnknownLink('198.51.100.7', $token);
		}
		$this->assertCount(1, $this->detectionsOf(ShareBruteforce::ID));
	}

	public function testGuessingTokensFromOneAddressBlocksItAtTheLimit(): void {
		for ($i = 1; $i <= 9; $i++) {
			$this->openUnknownLink('198.51.100.7', 'guessedToken' . $i);
		}
		$this->openUnknownLink('198.51.100.7', 'guessedToken1');
		$this->assertSame([], $this->detectionsOf(ShareBruteforce::ID), '9 different links are below the limit of 10; a repeated one counts once');

		$this->openUnknownLink('198.51.100.7', 'guessedToken10');
		$detections = $this->detectionsOf(ShareBruteforce::ID);
		$this->assertCount(1, $detections);
		$detection = $detections[0];
		$this->assertTrue($detection->isEnforced());
		$this->assertSame('198.51.100.7', $detection->getIp());
		$facts = $detection->getExplanationData()['facts'];
		$this->assertSame(ShareBruteforce::RULE_TOKENS, $facts['rule']);
		$this->assertSame(10, $facts['tokens']);
		$this->assertSame(11, $facts['attempts']);
		$this->assertSame(1, $facts['sampleFactor']);
		$this->assertSame([ResponseType::Ban->value, ResponseType::NotifyAdmin->value], array_column($detection->getActionList(), 'type'), 'Token guessing blocks and tells the admins');
		$this->assertCount(1, $this->bans->findActiveForKeys(['198.51.100.7'], time()));

		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$text = implode(' ', Server::get(NarrativeBuilder::class)->build($detection, $l)->happened);
		$this->assertStringContainsString('the address 198.51.100.7 tried 10 different share links that do not exist (11 attempts)', $text);
		$this->assertStringContainsString('The limit at that time was 10 links within 10 minutes.', $text);
		$this->assertStringNotContainsString('guessedToken', json_encode($detection->getExplanationData(), JSON_THROW_ON_ERROR));
	}

	public function testANetworkIsHeldToThreeTimesTheNumbers(): void {
		$this->openUnknownLink('198.51.100.50', 'staleLinkOfABystander');
		$n = 0;
		foreach (['198.51.100.1' => 8, '198.51.100.2' => 8, '198.51.100.3' => 7, '198.51.100.4' => 5] as $ip => $tokens) {
			for ($i = 0; $i < $tokens; $i++) {
				$this->openUnknownLink($ip, 'netToken' . $n++);
			}
		}
		$this->assertSame([], $this->detectionsOf(ShareBruteforce::ID), '29 different links from the /24, none of the addresses at 10: below 3 × 10');

		$this->openUnknownLink('198.51.100.4', 'netToken' . $n);
		$detections = $this->detectionsOf(ShareBruteforce::ID);
		$this->assertCount(1, $detections);
		$this->assertSame(ShareBruteforce::RULE_TOKENS_NETWORK, $detections[0]->getExplanationData()['facts']['rule']);
		foreach (['198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.4'] as $ip) {
			$this->assertNotSame([], $this->bans->findActiveForKeys([$ip], time()), $ip . ' is blocked');
		}
		$this->assertSame([], $this->bans->findActiveForKeys(['198.51.100.50'], time()), 'An address with one outdated link is not blocked on its own');
	}

	public function testIpv6IsCountedPerSlash64(): void {
		for ($i = 1; $i <= 10; $i++) {
			$this->openUnknownLink('2001:db8:1:2::' . dechex($i), 'v6Token' . $i);
		}
		$detections = $this->detectionsOf(ShareBruteforce::ID);
		$this->assertCount(1, $detections);
		$this->assertSame('2001:db8:1:2::/64', $detections[0]->getNetKey());
	}

	public function testLinksTriedBeforeAFloodCountOnce(): void {
		$detector = Server::get(ShareBruteforceDetector::class);
		$source = SourceKey::fromIp('198.51.100.7');
		for ($i = 1; $i <= 4; $i++) {
			$this->storeUnknownToken($source, 'beforeToken' . $i, 1);
		}
		$this->settings->setGlobal(GlobalSettings::ATTEMPTS_FLOOD_UNTIL, time() + 600);
		$detector->unknownToken($this->kept($source), null);
		$this->assertSame([], $this->detectionsOf(ShareBruteforce::ID), '4 links stay 4 when a flood starts');

		$this->storeUnknownToken($source, 'floodToken1');
		$detector->unknownToken($this->kept($source), null);
		$facts = $this->detectionsOf(ShareBruteforce::ID)[0]->getExplanationData()['facts'];
		$this->assertSame(14, $facts['tokens'], '4 before the flood, and one kept link that stands for 10');
		$this->assertSame(10, $facts['sampleFactor']);
	}

	public function testTheRecorderStoresTheWeightOfASampledAttempt(): void {
		$this->settings->setGlobal(GlobalSettings::ATTEMPTS_FLOOD_UNTIL, time() + 600);
		$recorder = new class(Server::get(AttemptMapper::class), Server::get(Fingerprinter::class), $this->settings, Server::get(\OCP\AppFramework\Utility\ITimeFactory::class)) extends AttemptRecorder {
			protected function oneIn(int $n): bool {
				return $n === AttemptRecorder::FLOOD_SAMPLE;
			}
		};
		$source = SourceKey::fromIp('198.51.100.9');
		$this->assertTrue($recorder->recordUnknownShareToken($source, 'kept-under-flood')->stored);
		$recorder->record(AttemptKind::PasswordLogin, $source, 'alice');
		$this->assertSame(10, $this->attempts->stats('ip_key', [$source->ipKey], [AttemptKind::UnknownShareToken], 0)->failuresEstimate());
		$this->assertSame(1, $this->attempts->stats('ip_key', [$source->ipKey], [AttemptKind::PasswordLogin], 0)->failuresEstimate(), 'Logins are never sampled');
	}

	public function testUnderAFloodCountsAreEstimatedButTwoLinksStillNeverFire(): void {
		$this->settings->setGlobal(GlobalSettings::ATTEMPTS_FLOOD_UNTIL, time() + 600);
		$detector = Server::get(ShareBruteforceDetector::class);
		$source = SourceKey::fromIp('198.51.100.7');

		$this->storeUnknownToken($source, 'sampledToken1');
		$this->storeUnknownToken($source, 'sampledToken2');
		$detector->unknownToken($this->kept($source), null);
		$this->assertSame([], $this->detectionsOf(ShareBruteforce::ID), '2 kept links stand for 20, but two links are never an attack');

		$this->storeUnknownToken($source, 'sampledToken3');
		$detector->unknownToken($this->kept($source), null);
		$detections = $this->detectionsOf(ShareBruteforce::ID);
		$this->assertCount(1, $detections);
		$facts = $detections[0]->getExplanationData()['facts'];
		$this->assertSame(10, $facts['sampleFactor']);
		$this->assertSame(30, $facts['tokens']);

		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$text = implode(' ', Server::get(NarrativeBuilder::class)->build($detections[0], $l)->happened);
		$this->assertStringContainsString('tried about 30 different share links', $text);
		$this->assertStringContainsString('only one in 10 unknown links was recorded', $text);

		// An attempt the recorder did not keep is not evaluated at all.
		$this->detections->delete($detections[0]);
		$detector->unknownToken(new AttemptRecord(AttemptKind::UnknownShareToken, $source, null, null, null, null, [], time(), false), null);
		$this->assertSame([], $this->detectionsOf(ShareBruteforce::ID));
	}

	public function testWrongPasswordsFromOneAddressBlockIt(): void {
		$owner = $this->user('ids-share-owner');
		$share = $this->linkShare($owner, self::SHARE_PASSWORD);
		for ($i = 0; $i < 4; $i++) {
			$this->enterWrongPassword('198.51.100.7', $share);
		}
		$this->assertSame([], $this->detectionsOf(ShareBruteforce::ID), '4 wrong passwords are below the limit of 5');

		$this->enterWrongPassword('198.51.100.7', $share);
		$detections = $this->detectionsOf(ShareBruteforce::ID);
		$this->assertCount(1, $detections);
		$this->assertSame(ShareBruteforce::RULE_PASSWORD_SOURCE, $detections[0]->getExplanationData()['facts']['rule']);
		$this->assertSame((int)$share->getId(), $detections[0]->getShareId());
		$this->assertNull($detections[0]->getUid(), 'About the address: it is not shown on the owner\'s security page');
		$this->assertSame([$owner->getUID()], $detections[0]->getExplanationData()['facts']['managers']);
		$this->assertSame('198.51.100.7', $detections[0]->getIp());
		$this->assertSame(['ban' => true, 'notify_admin' => true], array_column($detections[0]->getActionList(), 'enforced', 'type'));
		$this->assertNotSame([], $this->bans->findActiveForKeys(['198.51.100.7'], time()));
		$this->assertSame([], $this->notifications(ShareOwnerAlerts::SUBJECT), 'One address guessing is blocked; the owner is not bothered');
	}

	public function testWrongPasswordsFromManyAddressesTellTheOwnerOnce(): void {
		$owner = $this->user('ids-share-owner');
		$share = $this->linkShare($owner, self::SHARE_PASSWORD, 'Budget 2027.ods');
		$source = SourceKey::fromIp('203.0.113.1');
		for ($i = 1; $i <= 18; $i++) {
			$this->storeWrongPassword(SourceKey::fromIp('203.0.113.' . $i), (int)$share->getId());
		}
		$this->enterWrongPassword('203.0.113.19', $share);
		$this->assertSame([], $this->detectionsOf(ShareBruteforce::ID), '19 wrong passwords are below the limit of 20');

		$this->enterWrongPassword('203.0.113.20', $share);
		$detections = $this->detectionsOf(ShareBruteforce::ID);
		$this->assertCount(1, $detections);
		$detection = $detections[0];
		$this->assertSame(ShareBruteforce::RULE_PASSWORD_SHARE, $detection->getExplanationData()['facts']['rule']);
		$this->assertNull($detection->getIp(), 'The detection is about the share, not one address');
		$this->assertSame([], $this->bans->findActiveForKeys([$source->ipKey], time()), 'Nobody is blocked for one wrong password');
		$this->assertSame(
			[ResponseType::NotifyAdmin->value => true, ResponseType::NotifyShareOwner->value => true],
			array_column($detection->getActionList(), 'enforced', 'type'),
		);

		for ($i = 21; $i <= 25; $i++) {
			$this->enterWrongPassword('203.0.113.' . $i, $share);
		}
		$this->assertCount(1, $this->detectionsOf(ShareBruteforce::ID), 'Further wrong passwords merge into the detection');
		$notifications = $this->notifications(ShareOwnerAlerts::SUBJECT);
		$this->assertCount(1, $notifications, 'The owner is told once');
		$this->assertSame($owner->getUID(), $notifications[0]->getUser());

		$prepared = Server::get(ShareOwnerNotifier::class)->prepare($notifications[0], 'en');
		$this->assertSame('Someone is trying to guess the password of your share', $prepared->getParsedSubject());
		$this->assertStringContainsString('your share "Budget 2027.ods" (25 wrong passwords within 1 hour)', $prepared->getParsedMessage());
		$this->assertStringContainsString('If the password is short, change it, or turn the link off.', $prepared->getParsedMessage());
		$this->assertStringContainsString('/f/' . $share->getNodeId(), $prepared->getLink());
		$actions = [];
		foreach ($prepared->getParsedActions() as $action) {
			$actions[$action->getParsedLabel()] = [$action->getRequestType(), $action->getLink()];
		}
		$this->assertSame(['Open share settings', 'Disable link'], array_keys($actions));
		$this->assertSame('POST', $actions['Disable link'][0]);
		$this->assertStringEndsWith('/apps/intrusion_detection/api/v1/share-alerts/' . $detection->getId() . '/disable', $actions['Disable link'][1]);
		$this->assertStringNotContainsString($share->getToken(), json_encode($prepared->getParsedActions(), JSON_THROW_ON_ERROR) . $prepared->getLink());
	}

	public function testTheOwnerAndWhoeverCreatedTheLinkAreToldAndEmailedIfTheyHaveAnAddress(): void {
		$creator = $this->user('ids-share-creator', 'creator@example.com');
		$fileOwner = $this->user('ids-share-file-owner');
		$share = $this->linkShare($creator, self::SHARE_PASSWORD, 'Plans.pdf', $fileOwner);
		$detection = $this->shareDetection($share);
		$this->assertSame($creator->getUID(), $detection->getUid());
		$this->assertSame([$creator->getUID(), $fileOwner->getUID()], $detection->getExplanationData()['facts']['managers']);

		$mailed = [];
		$mails = $this->createMock(Mails::class);
		$mails->method('send')->willReturnCallback(static function (IUser $user, MailContent $content) use (&$mailed): bool {
			if ($user->getEMailAddress() === null) {
				return false;
			}
			$mailed[$user->getUID()] = $content;
			return true;
		});
		CapturingNotificationApp::$notifications = [];
		$alerts = new ShareOwnerAlerts(
			Server::get(ShareLinks::class),
			Server::get(ShareBruteforce::class),
			Server::get(IUserManager::class),
			Server::get(INotificationManager::class),
			$mails,
			Server::get(IFactory::class),
			Server::get(IURLGenerator::class),
			Server::get(ITimeFactory::class),
		);
		$result = $alerts->alert($detection, $share);

		$this->assertSame(['recipients' => [$creator->getUID(), $fileOwner->getUID()], 'emails' => 1], $result);
		$this->assertSame([$creator->getUID(), $fileOwner->getUID()], array_map(static fn (INotification $n): string => $n->getUser(), $this->notifications(ShareOwnerAlerts::SUBJECT)));
		$this->assertSame([$creator->getUID()], array_keys($mailed), 'Only the person with an email address gets an email');
		$mail = $mailed[$creator->getUID()];
		$this->assertSame('Someone is trying to guess the password of your share', $mail->subject);
		$this->assertStringContainsString('your share "Plans.pdf" (21 wrong passwords within 1 hour)', implode(' ', $mail->paragraphs));
		$this->assertSame('Open share settings', $mail->buttonText);
		$this->assertStringContainsString('/f/424242', (string)$mail->buttonUrl);
		$this->assertStringNotContainsString($share->getToken(), json_encode(get_object_vars($mail), JSON_THROW_ON_ERROR));

		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$done = implode(' ', Server::get(NarrativeBuilder::class)->build($this->detections->findById($detection->getId()), $l)->done);
		$this->assertStringContainsString('Told ' . $creator->getUID() . ', ' . $fileOwner->getUID() . ', who manage the share', $done);
	}

	public function testDisableLinkIsOnlyForTheOwnerAndCanBeRepeated(): void {
		$owner = $this->user('ids-share-owner');
		$stranger = $this->user('ids-share-stranger');
		$share = $this->linkShare($owner, self::SHARE_PASSWORD);
		$detection = $this->shareDetection($share);

		$response = $this->controllerFor($stranger)->disable($detection->getId());
		$this->assertSame(Http::STATUS_NOT_FOUND, $response->getStatus());
		$this->assertSame($share->getId(), Server::get(IShareManager::class)->getShareById($share->getFullId())->getId(), 'The link still works');

		$response = $this->controllerFor($owner)->disable($detection->getId());
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame(['status' => ShareLinks::DISABLED], $response->getData());
		try {
			Server::get(IShareManager::class)->getShareByToken($share->getToken());
			$this->fail('The link was turned off');
		} catch (ShareNotFound) {
		}

		$response = $this->controllerFor($owner)->disable($detection->getId());
		$this->assertSame(['status' => ShareLinks::ALREADY_GONE], $response->getData(), 'Doing it again is harmless');
		$this->assertSame(Http::STATUS_NOT_FOUND, $this->controllerFor($stranger)->disable($detection->getId())->getStatus(), 'Strangers do not even learn that the link is gone');
		$this->assertSame(Http::STATUS_NOT_FOUND, $this->controllerFor($owner)->disable($detection->getId() + 1000)->getStatus());

		// The notification about a link that is gone disappears.
		$notification = Server::get(\OCP\Notification\IManager::class)->createNotification();
		$notification->setApp(Application::APP_ID)->setUser($owner->getUID())->setDateTime(new \DateTime())
			->setObject(ShareOwnerAlerts::OBJECT_TYPE, (string)$detection->getId())
			->setSubject(ShareOwnerAlerts::SUBJECT, ['detection' => $detection->getId()]);
		$this->expectException(AlreadyProcessedException::class);
		Server::get(ShareOwnerNotifier::class)->prepare($notification, 'en');
	}

	public function testDisableLinkRefusesDetectionsOfOtherChecks(): void {
		$owner = $this->user('ids-share-owner');
		$share = $this->linkShare($owner, self::SHARE_PASSWORD);
		$detection = $this->shareDetection($share);
		$detection->setCheckId('credential_stuffing');
		$this->detections->update($detection);
		$this->assertSame(Http::STATUS_NOT_FOUND, $this->controllerFor($owner)->disable($detection->getId())->getStatus());
		$this->assertSame($share->getId(), Server::get(IShareManager::class)->getShareById($share->getFullId())->getId());
	}

	public function testOffSkipsAllWork(): void {
		$this->settings->setMode(ShareBruteforce::ID, Mode::Off);
		for ($i = 1; $i <= 12; $i++) {
			$this->openUnknownLink('198.51.100.7', 'offToken' . $i);
		}
		$this->assertSame(0, $this->rows(AttemptMapper::TABLE), 'Nothing is recorded');
		$this->assertSame([], $this->detectionsOf(ShareBruteforce::ID));
	}

	public function testObserveRecordsWhatItWouldHaveDone(): void {
		$this->settings->setGlobal(GlobalSettings::LEARNING_UNTIL, time() + 86400);
		for ($i = 1; $i <= 10; $i++) {
			$this->openUnknownLink('198.51.100.7', 'learningToken' . $i);
		}
		$detections = $this->detectionsOf(ShareBruteforce::ID);
		$this->assertCount(1, $detections);
		$this->assertFalse($detections[0]->isEnforced());
		$this->assertSame([['type' => ResponseType::Ban->value, 'enforced' => false], ['type' => ResponseType::NotifyAdmin->value, 'enforced' => false]], $detections[0]->getActionList());
		$this->assertSame([], $this->bans->findActiveForKeys(['198.51.100.7'], time()));
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$this->assertSame('Would have: Block the address for hours, longer if it comes back.', Server::get(NarrativeBuilder::class)->build($detections[0], $l)->done[0]);
	}

	private function openUnknownLink(string $ip, string $token): void {
		$this->remoteAddress = $ip;
		$controller = Server::get(ShareController::class);
		$controller->setToken($token);
		$this->assertFalse($controller->isValidToken());
		// What PublicShareMiddleware does for every share page route with an unknown token.
		$controller->shareNotFound();
	}

	private function enterWrongPassword(string $ip, IShare $share): void {
		$this->remoteAddress = $ip;
		$controller = Server::get(ShareController::class);
		$controller->setToken($share->getToken());
		$this->assertTrue($controller->isValidToken());
		$controller->authenticate('not-the-password');
	}

	private function storeUnknownToken(SourceKey $source, string $token, int $weight = AttemptRecorder::FLOOD_SAMPLE): void {
		$this->attempts->insert(AttemptKind::UnknownShareToken, $source->ipKey, $source->netKey, bin2hex(Server::get(Fingerprinter::class)->shareToken($token)), null, null, null, time(), $weight);
	}

	private function storeWrongPassword(SourceKey $source, int $shareId): void {
		$this->attempts->insert(AttemptKind::WrongSharePassword, $source->ipKey, $source->netKey, null, null, $shareId, null, time());
	}

	private function kept(SourceKey $source): AttemptRecord {
		return new AttemptRecord(AttemptKind::UnknownShareToken, $source, null, null, null, null, [], time(), true);
	}

	private function shareDetection(IShare $share): Detection {
		for ($i = 1; $i <= 20; $i++) {
			$this->storeWrongPassword(SourceKey::fromIp('203.0.113.' . $i), (int)$share->getId());
		}
		$this->enterWrongPassword('203.0.113.21', $share);
		$detections = $this->detectionsOf(ShareBruteforce::ID);
		$this->assertCount(1, $detections);
		return $detections[0];
	}

	private function controllerFor(IUser $user): ShareAlertController {
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturn($user);
		return new ShareAlertController(
			$this->createMock(IRequest::class),
			$this->shareLinks(),
			Server::get(ShareOwnerAlerts::class),
			$session,
		);
	}

	/**
	 * Share links with the real share manager, except that deleting a share
	 * only removes its row: core's deletion also looks at the shared file,
	 * and these tests do not set up a user's filesystem.
	 */
	private function shareLinks(): ShareLinks {
		$real = Server::get(IShareManager::class);
		$manager = $this->createMock(IShareManager::class);
		$manager->method('getShareById')->willReturnCallback(static fn (string $id, ?string $recipient = null, bool $onlyValid = true): IShare => $real->getShareById($id, $recipient, $onlyValid));
		$manager->method('deleteShare')->willReturnCallback(function (IShare $share): void {
			$qb = $this->db->getQueryBuilder();
			$qb->delete('share')->where($qb->expr()->eq('id', $qb->createNamedParameter((int)$share->getId(), IQueryBuilder::PARAM_INT)))->executeStatement();
		});
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $class): object => $class === IShareManager::class ? $manager : Server::get($class));
		return new ShareLinks($container, $this->detections, Server::get(IURLGenerator::class), Server::get(AuditLogger::class));
	}
}
