<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Core\Events\BeforePasswordResetEvent;
use OC\Core\Events\PasswordResetEvent;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AccountTakeover;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\LockLinkMapper;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Response\Handlers\LockLinkHandler;
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCP\Authentication\Events\AppPasswordCreatedEvent;
use OCP\Authentication\Token\IToken;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Concept section 10.14 and the tests of section 20: the points, the
 * risky-login window, admin, occ and reset changes never counting, and the
 * lock link only for email changes with a previous address.
 */
#[Group('DB')]
class AccountTakeoverTest extends TakeoverTestCase {
	private DetectionMapper $detections;

	protected function setUp(): void {
		parent::setUp();
		$this->detections = Server::get(DetectionMapper::class);
	}

	public function testEmailChangeAndAppPasswordAfterARiskyLoginFire(): void {
		$user = $this->newUser('ids-to', 'owner@example.com');
		$session = $this->loginAs($user, true);

		$user->setSystemEMailAddress('attacker@evil.example');
		$this->assertNull($this->takeover($user), 'An email change alone counts 2 points, below 3');
		$this->appPassword($user);

		$detection = $this->takeover($user);
		$this->assertNotNull($detection);
		$this->assertTrue($detection->isEnforced());
		$facts = $detection->getExplanationData()['facts'];
		$this->assertSame([AccountTakeover::RULE_RISKY_LOGIN], $facts['rules']);
		$this->assertSame(3, $facts['sessionPoints']);
		$this->assertSame($session['id'], $facts['sessionTokenId']);
		$this->assertSame('o***@example.com', $facts['previousAddress']);
		$this->assertSame(['email_changed', 'app_password_created'], array_column($facts['changes'], 'type'));

		$actions = array_column($detection->getActionList(), null, 'type');
		$this->assertTrue($actions[ResponseType::LockLink->value]['enforced']);

		$this->assertCount(1, $this->sentTo, 'One lock link');
		[$address, $mail] = $this->sentTo[0];
		$this->assertSame('owner@example.com', $address, 'The lock link goes to the previous address');
		$this->assertMatchesRegularExpression('#/apps/intrusion_detection/lock/\d+/[A-Za-z0-9]{43}$#', (string)$mail->buttonUrl);
		$this->assertSame([$user->getUID()], array_values(array_unique(array_column($this->mailed, 0))), 'The user is told at the current address');

		$text = implode(' ', Server::get(NarrativeBuilder::class)->build($detection, Server::get(IFactory::class)->get(Application::APP_ID, 'en'))->done);
		$this->assertStringContainsString('emailed to the previous address o***@example.com', $text);
	}

	public function testAMergedHitSendsNoSecondLockLink(): void {
		$user = $this->newUser('ids-to', 'owner@example.com');
		$this->loginAs($user, true);
		$user->setSystemEMailAddress('attacker@evil.example');
		$this->appPassword($user);
		$this->appPassword($user);

		$this->assertCount(1, $this->detectionsOf($user), 'Repeated firing updates one detection');
		$this->assertCount(1, $this->sentTo);
		$this->assertSame(2, $this->takeover($user)?->getHits());
	}

	public function testAConfirmedLoginNeedsTheHigherLimitOfAnySession(): void {
		$user = $this->newUser('ids-to', 'owner@example.com');
		$this->loginAs($user, false);
		$user->setSystemEMailAddress('new@example.com');
		$this->appPassword($user);
		$this->assertNull($this->takeover($user), '3 points from a confirmed login stay below 5');

		$this->appPassword($user);
		$this->appPassword($user);
		$detection = $this->takeover($user);
		$this->assertNotNull($detection, '5 points from any session within 30 minutes');
		$this->assertSame([AccountTakeover::RULE_ANY_SESSION], $detection->getExplanationData()['facts']['rules']);
		$this->assertSame(5, $detection->getExplanationData()['facts']['anyPoints']);
	}

	public function testChangesLongAfterTheRiskyLoginDoNotCount(): void {
		$user = $this->newUser('ids-to', 'owner@example.com');
		$this->loginAs($user, true, time() - 7200);
		$user->setSystemEMailAddress('attacker@evil.example');
		$this->appPassword($user);
		$this->assertNull($this->takeover($user), 'The window of 60 minutes after the risky login is over');
	}

	public function testChangesByAnAdministratorNeverCount(): void {
		$user = $this->newUser('ids-to', 'owner@example.com');
		$admin = $this->newUser('ids-admin');
		Server::get(IGroupManager::class)->get('admin')?->addUser($admin);
		$this->loginAs($user, true);
		$this->sessionUser = $admin;

		$user->setSystemEMailAddress('new@example.com');
		$user->setPassword('A-new-test-password-for-the-user');
		foreach (range(1, 4) as $i) {
			$this->appPassword($user);
		}

		$this->assertNull($this->takeover($user));
		$this->assertSame([], $this->changes($user->getUID()));
		$admins = $this->changes($user->getUID(), SecurityChangeLog::VIA_ADMIN);
		$this->assertCount(6, $admins);
		$this->assertSame([$admin->getUID()], array_values(array_unique(array_column($admins, 'actor_uid'))));
		$this->assertSame([], $this->sentTo);
	}

	public function testChangesWithOccNeverCount(): void {
		$user = $this->newUser('ids-to', 'owner@example.com');
		$this->actor = 'occ';
		$user->setSystemEMailAddress('new@example.com');
		$user->setPassword('A-new-test-password-for-the-user');
		foreach (range(1, 4) as $i) {
			$this->appPassword($user);
		}
		$this->assertNull($this->takeover($user));
		$occ = $this->changes($user->getUID(), SecurityChangeLog::VIA_OCC);
		$this->assertCount(6, $occ);
		$this->assertNull($occ[0]['session_token_id'], 'occ has no session');
	}

	public function testAPasswordResetByEmailNeverCounts(): void {
		$user = $this->newUser('ids-to', 'owner@example.com');
		$this->loginAs($user, true);
		$user->setSystemEMailAddress('attacker@evil.example');

		$dispatcher = Server::get(IEventDispatcher::class);
		$dispatcher->dispatchTyped(new BeforePasswordResetEvent($user, 'A-new-test-password-for-the-user'));
		$user->setPassword('A-new-test-password-for-the-user');
		$dispatcher->dispatchTyped(new PasswordResetEvent($user, 'A-new-test-password-for-the-user'));

		$this->assertNull($this->takeover($user), '2 points: the reset adds nothing');
		$this->assertSame(['password_changed'], array_column($this->changes($user->getUID(), SecurityChangeLog::VIA_RESET), 'type'));

		$user->setPassword('Another-new-test-password-for-the-user');
		$this->assertNotNull($this->takeover($user), 'A password change after the reset counts again');
	}

	public function testNoLockLinkWithoutAnEmailChange(): void {
		$user = $this->newUser('ids-to', 'owner@example.com');
		$this->loginAs($user, true);
		foreach (range(1, 3) as $i) {
			$this->appPassword($user);
		}
		$detection = $this->takeover($user);
		$this->assertNotNull($detection);
		$this->assertSame([], $this->sentTo);
		$action = array_column($detection->getActionList(), null, 'type')[ResponseType::LockLink->value];
		$this->assertSame(LockLinkHandler::NOTE_NO_EMAIL_CHANGE, $action['note']);
	}

	public function testNoLockLinkWhenThereWasNoPreviousAddress(): void {
		$user = $this->newUser('ids-to');
		$this->loginAs($user, true);
		$user->setSystemEMailAddress('attacker@evil.example');
		$this->appPassword($user);

		$detection = $this->takeover($user);
		$this->assertNotNull($detection);
		$this->assertSame([], $this->sentTo, 'Nothing is sent: there is no previous address');
		$this->assertSame(0, $this->lockLinkCount());
		$this->assertNull($detection->getExplanationData()['facts']['emailChangeId']);
	}

	public function testAUserWithoutAnyEmailAddressIsReportedToTheAdministrators(): void {
		$user = $this->newUser('ids-to', 'owner@example.com');
		$this->loginAs($user, true);
		$user->setSystemEMailAddress('');
		$this->appPassword($user);
		$detection = $this->takeover($user);
		$this->assertNotNull($detection);
		$this->assertFalse($detection->getExplanationData()['facts']['userHasEmail']);
		$this->assertCount(1, $this->sentTo, 'The removed address still gets the lock link');
		$text = implode(' ', Server::get(NarrativeBuilder::class)->build($detection, Server::get(IFactory::class)->get(Application::APP_ID, 'en'))->happened);
		$this->assertStringContainsString('has no email address now', $text);
	}

	public function testObserveRecordsButSendsNothing(): void {
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode(AccountTakeover::ID), Mode::Observe->value);
		$user = $this->newUser('ids-to', 'owner@example.com');
		$this->loginAs($user, true);
		$user->setSystemEMailAddress('attacker@evil.example');
		$this->appPassword($user);
		$detection = $this->takeover($user);
		$this->assertNotNull($detection);
		$this->assertFalse($detection->isEnforced());
		$this->assertSame([], $this->sentTo);
		$this->assertSame([], $this->mailed);
	}

	public function testOffRecordsTheChangesButNoDetection(): void {
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode(AccountTakeover::ID), Mode::Off->value);
		$user = $this->newUser('ids-to', 'owner@example.com');
		$this->loginAs($user, true);
		$user->setSystemEMailAddress('attacker@evil.example');
		$this->appPassword($user);
		$this->assertNull($this->takeover($user));
		$this->assertCount(2, $this->changes($user->getUID()), 'The log is kept for the personal page and reports');
	}

	public function testThePointsAreConfigurable(): void {
		$this->settings->setParam(AccountTakeover::ID, 'points_app_password_created', 0);
		$user = $this->newUser('ids-to', 'owner@example.com');
		$this->loginAs($user, true);
		$user->setSystemEMailAddress('attacker@evil.example');
		$this->appPassword($user);
		$this->assertNull($this->takeover($user), 'App passwords count 0 now');
		$this->settings->setParam(AccountTakeover::ID, AccountTakeover::PARAM_MIN_POINTS, 2);
		$this->appPassword($user);
		$this->assertNotNull($this->takeover($user));
	}

	public function testTheProtectionMasterSwitchStopsTheLog(): void {
		$this->settings->setGlobal(GlobalSettings::ENABLED, false);
		$user = $this->newUser('ids-to', 'owner@example.com');
		$this->loginAs($user, true);
		$user->setSystemEMailAddress('attacker@evil.example');
		$this->assertSame([], $this->changes($user->getUID(), null));
	}

	private function appPassword(IUser $user): IToken {
		$token = $this->token($user, IToken::PERMANENT_TOKEN, 'Sync client');
		$created = $this->tokens->getTokenById($token['id']);
		Server::get(IEventDispatcher::class)->dispatchTyped(new AppPasswordCreatedEvent($created));
		return $created;
	}

	private function takeover(IUser $user): ?Detection {
		return $this->detectionsOf($user)[0] ?? null;
	}

	/**
	 * @return list<Detection>
	 */
	private function detectionsOf(IUser $user): array {
		return $this->detections->findList(new DetectionFilter(checkIds: [AccountTakeover::ID], uid: $user->getUID()));
	}

	private function lockLinkCount(): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*'))->from(LockLinkMapper::TABLE);
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}
}
