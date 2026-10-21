<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Admin\LookupService;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\BreachedPassword;
use OCA\IntrusionDetection\Check\Checks\BreachedPasswordDetector;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused;
use OCA\IntrusionDetection\Check\Checks\StepUpRefusedClient;
use OCA\IntrusionDetection\Check\Checks\StepUpUnconfirmed;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\LoginDetections;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpReference;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Response\AccountProtection;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\PasswordChangeFlag;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\Config\IUserConfig;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Server;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Concept section 11.5: which password logins need extra confirmation,
 * how they are confirmed, and what happens when nothing can confirm them.
 */
#[Group('DB')]
class StepUpTest extends StepUpTestCase {
	private IUser $alice;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-stepup', 'alice@example.com');
	}

	public function testANormalLoginIsNotHeldBack(): void {
		$this->login($this->alice);
		$this->assertNull($this->stepUp());
		$this->assertSame([], $this->mailed);
		$this->assertSame(0, $this->unconfirmedRows());
		$this->assertNull($this->state->get(SessionState::CONFIRMATION));
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function reasons(): array {
		return [
			'flagged source' => [StepUpPolicy::FlaggedSource->value],
			'sprayed password' => [StepUpPolicy::SprayedPassword->value],
			'protected account' => [StepUpPolicy::ProtectedAccount->value],
			'breached password' => [StepUpPolicy::BreachedPassword->value],
		];
	}

	#[DataProvider('reasons')]
	public function testEachReasonWaitsForTheEmailCode(string $policy): void {
		$this->give(StepUpPolicy::from($policy), $this->alice);
		$this->login($this->alice);

		$stepUp = $this->stepUp();
		$this->assertNotNull($stepUp);
		$this->assertSame(StepUpState::PENDING, $stepUp->status);
		$this->assertSame([$policy], $stepUp->policies);
		$this->assertSame([IConfirmationMethod::EMAIL_CODE], $stepUp->methods);
		$this->assertSame($stepUp->started + 900, $stepUp->deadline);
		$this->assertNotNull($stepUp->codeHash);
		$this->assertSame('482915', $this->lastCode($this->alice->getUID()), 'The code went to the account\'s address');
		$this->assertSame(1, $this->unconfirmedRows(), 'Remembered on the server, so the session cannot come back without it');
		$this->assertTrue(Server::get(UnconfirmedSessions::class)->mayExist());
	}

	public function testASprayedPasswordIsReportedAndRequiresANewPassword(): void {
		$this->give(StepUpPolicy::SprayedPassword, $this->alice);
		$this->login($this->alice);
		$detections = $this->detectionsOf(PasswordSpraying::ID);
		$this->assertCount(1, $detections);
		$facts = $detections[0]->getExplanationData()['facts'];
		$this->assertSame(PasswordSpraying::RULE_LOGIN, $facts['rule']);
		$this->assertSame($this->alice->getUID(), $detections[0]->getUid());
		$types = array_column($detections[0]->getActionList(), 'enforced', 'type');
		$this->assertSame(['force_password_change' => true, 'step_up' => true, 'notify_admin' => true, 'notify_user' => true], $types, 'The login responses only: no block for a successful login');
		$this->assertTrue(Server::get(PasswordChangeFlag::class)->isRequired($this->alice->getUID()));
		$this->assertCount(1, $this->notificationsFor($this->alice->getUID(), UserAlerts::SUBJECT));
		$this->assertSame(['uid' => $this->alice->getUID(), 'ids' => [$detections[0]->getId()]], $this->state->get(SessionState::LOGIN_DETECTIONS), 'Linked to the session at its first request');
	}

	public function testAReasonOfAnObservingCheckDoesNotAsk(): void {
		$this->give(StepUpPolicy::SprayedPassword, $this->alice);
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);
		$this->login($this->alice);
		$this->assertNull($this->stepUp());
		$this->assertFalse($this->detectionsOf(PasswordSpraying::ID)[0]->isEnforced(), 'Recorded as "would have"');
	}

	public function testSwitchingTheStepUpResponseOffStopsTheConfirmation(): void {
		$this->give(StepUpPolicy::SprayedPassword, $this->alice);
		$this->settings->setResponses(PasswordSpraying::ID, [ResponseType::Ban, ResponseType::FlagPassword, ResponseType::NotifyAdmin]);
		$this->login($this->alice);
		$this->assertNull($this->stepUp());
	}

	public function testAccountsWithASecondFactorAreNotAskedAgain(): void {
		$this->hasSecondFactor = true;
		$this->give(StepUpPolicy::FlaggedSource, $this->alice);
		$this->login($this->alice);
		$this->assertNull($this->stepUp(), 'Core\'s challenge right after the password is the confirmation');
		$this->assertSame([], $this->mailed);
		$this->assertSame('second_factor', $this->state->get(SessionState::CONFIRMATION)['by'] ?? null);
		$this->assertSame(0, $this->unconfirmedRows());
	}

	public function testASprayedPasswordIsReportedEvenWithASecondFactor(): void {
		$this->hasSecondFactor = true;
		$this->give(StepUpPolicy::SprayedPassword, $this->alice);
		$this->login($this->alice);
		$this->assertNull($this->stepUp());
		$this->assertTrue(Server::get(PasswordChangeFlag::class)->isRequired($this->alice->getUID()), 'Attackers know the password: it must change');
		$this->assertCount(1, $this->notificationsFor($this->alice->getUID(), UserAlerts::SUBJECT));
	}

	public function testNothingIsAskedWhileIntrusionDetectionIsOff(): void {
		$this->give(StepUpPolicy::FlaggedSource, $this->alice);
		$this->settings->setGlobal(GlobalSettings::ENABLED, false);
		$this->login($this->alice);
		$this->assertNull($this->stepUp());
	}

	public function testTrustedNetworksSkipFlaggedSourcesButNotOtherReasons(): void {
		$this->give(StepUpPolicy::FlaggedSource, $this->alice);
		Server::get(TrustedNetworks::class)->trust($this->alice->getUID(), SourceKey::fromIp('198.51.100.200'));
		$this->login($this->alice);
		$this->assertNull($this->stepUp(), 'Another address of the trusted /24');

		$bob = $this->user('ids-stepup-bob', 'bob@example.com');
		$this->session->id = null;
		$this->login($bob);
		$this->assertNotNull($this->stepUp(), 'The trust is the user\'s own');

		Server::get(AccountProtection::class)->protect($this->alice->getUID(), time() + 3600);
		$this->session->id = null;
		$this->session->clear();
		$this->login($this->alice);
		$this->assertSame([StepUpPolicy::ProtectedAccount->value], $this->stepUp()?->policies);
	}

	public function testAddressesOnTheAllowlistAreNeverAsked(): void {
		$this->give(StepUpPolicy::FlaggedSource, $this->alice);
		$this->bypassListed = true;
		$this->login($this->alice);
		$this->assertNull($this->stepUp());
	}

	public function testAppPasswordsTokensAndSingleSignOnAreNeverAsked(): void {
		$this->give(StepUpPolicy::ProtectedAccount, $this->alice);
		$this->headers['Authorization'] = 'Basic ' . base64_encode('alice:app-password');
		$this->login($this->alice, 'xxxxx-xxxxx-xxxxx-xxxxx-xxxxx', tokenLogin: true);
		$this->assertNull($this->stepUp(), 'App password');

		$this->headers = ['Authorization' => 'Bearer abc'];
		$this->login($this->alice, '', tokenLogin: true);
		$this->assertNull($this->stepUp(), 'Bearer token');

		$this->headers = [];
		$this->method = 'GET';
		$this->pathInfo = '/apps/user_saml/saml/acs';
		$this->login($this->alice);
		$this->assertNull($this->stepUp(), 'A login that is neither the login form nor Basic auth');
	}

	public function testWithoutEmailTheLoginIsRefusedAndTheAdministratorsAreTold(): void {
		$bob = $this->user('ids-stepup-noemail', null);
		$this->give(StepUpPolicy::FlaggedSource, $bob);
		$this->login($bob);

		$stepUp = $this->stepUp();
		$this->assertSame(StepUpState::REFUSED, $stepUp?->status);
		$this->assertSame([], $this->mailed, 'Never an email to an account without an address');
		$detections = $this->detectionsOf(StepUpRefused::ID);
		$this->assertCount(1, $detections);
		$this->assertSame(StepUpReference::of($detections[0]->getId()), $stepUp->reference);
		$this->assertNotEmpty($this->notificationsFor('admin', AdminAlerts::SUBJECT), 'The administrators are told');
		$this->assertSame(1, $this->unconfirmedRows());

		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$found = Server::get(LookupService::class)->lookup(strtolower((string)$stepUp->reference), $l);
		$this->assertSame('reference', $found['kind']);
		$this->assertSame($detections[0]->getId(), $found['detections'][0]['id'] ?? null, 'The reference leads the administrator to the refusal');
	}

	public function testAFailingEmailFallsBackToThePolicy(): void {
		$this->mailWorks = false;
		$this->give(StepUpPolicy::FlaggedSource, $this->alice);
		$this->login($this->alice);
		$this->assertSame(StepUpState::REFUSED, $this->stepUp()?->status);
	}

	public function testAllowAndNotifyLetsTheLoginInAndTellsUserAndAdministrators(): void {
		$this->settings->setGlobal(StepUpPolicy::FlaggedSource->settingKey(), 'allow_notify');
		$bob = $this->user('ids-stepup-notify', null);
		$this->give(StepUpPolicy::FlaggedSource, $bob);
		$this->login($bob);

		$this->assertNull($this->stepUp());
		$this->assertSame('none', $this->state->get(SessionState::CONFIRMATION)['by'] ?? null, 'The session counts as unconfirmed');
		$detection = $this->detectionsOf(StepUpUnconfirmed::ID)[0];
		$this->assertSame(['notify_admin', 'notify_user'], array_column($detection->getActionList(), 'type'));
		$this->assertCount(1, $this->notificationsFor($bob->getUID(), UserAlerts::SUBJECT));
		$this->assertFalse(Server::get(PasswordChangeFlag::class)->isRequired($bob->getUID()));
		$this->assertSame([$detection->getId()], $this->state->get(SessionState::LOGIN_DETECTIONS)['ids'] ?? null);
	}

	public function testAllowAndForceChangeRequiresANewPassword(): void {
		$bob = $this->user('ids-stepup-breached', null);
		$this->give(StepUpPolicy::BreachedPassword, $bob);
		$this->login($bob);

		$this->assertNull($this->stepUp());
		$this->assertTrue(Server::get(PasswordChangeFlag::class)->isRequired($bob->getUID()), 'The forced password change then sends the session to the password page');
		$detection = $this->detectionsOf(StepUpUnconfirmed::ID)[0];
		$this->assertSame(['force_password_change'], array_column($detection->getActionList(), 'type'));
		$this->assertSame([], $this->notificationsFor($bob->getUID(), UserAlerts::SUBJECT));
	}

	public function testOneRefusingReasonRefusesEvenWhenAnotherAllows(): void {
		$bob = $this->user('ids-stepup-two', null);
		$this->give(StepUpPolicy::BreachedPassword, $bob);
		$this->give(StepUpPolicy::ProtectedAccount, $bob);
		$this->login($bob);
		$this->assertSame(StepUpState::REFUSED, $this->stepUp()?->status);
		$this->assertSame([StepUpPolicy::ProtectedAccount->value, StepUpPolicy::BreachedPassword->value], $this->stepUp()?->policies);
	}

	public function testAppsSendingThePasswordAreRefusedAndTheUserIsToldOnceADay(): void {
		$this->give(StepUpPolicy::ProtectedAccount, $this->alice);
		$this->basicAuth($this->alice);
		$this->login($this->alice);
		$this->assertSame(StepUpState::REFUSED_CLIENT, $this->stepUp()?->status);
		$this->assertNull($this->lastCode($this->alice->getUID()), 'No code: an app cannot enter it');

		for ($i = 0; $i < 3; $i++) {
			$this->session->clear();
			$this->session->id = null;
			$this->login($this->alice);
			$this->assertSame(StepUpState::REFUSED_CLIENT, $this->stepUp()?->status);
		}
		$detections = $this->detectionsOf(StepUpRefusedClient::ID);
		$this->assertCount(1, $detections, 'One detection per account and day');
		$this->assertSame(4, $detections[0]->getHits());
		$this->assertCount(1, $this->notificationsFor($this->alice->getUID(), UserAlerts::SUBJECT), 'Told once a day');
	}

	public function testRefusedAppsAreOneDetectionPerAddress(): void {
		$this->give(StepUpPolicy::ProtectedAccount, $this->alice);
		$this->basicAuth($this->alice);
		foreach (['198.51.100.7', '203.0.113.9'] as $address) {
			$this->remoteAddress = $address;
			$this->session->clear();
			$this->session->id = null;
			$this->login($this->alice);
		}
		$this->assertCount(2, $this->detectionsOf(StepUpRefusedClient::ID), 'Each address can be answered on its own');
	}

	public function testSprayedPasswordLoginsAreOneDetectionPerAddress(): void {
		$this->give(StepUpPolicy::SprayedPassword, $this->alice);
		foreach (['198.51.100.7', '203.0.113.9'] as $address) {
			$this->remoteAddress = $address;
			$this->session->clear();
			$this->session->id = null;
			$this->login($this->alice);
		}
		$detections = $this->detectionsOf(PasswordSpraying::ID);
		$this->assertEqualsCanonicalizing(['198.51.100.7', '203.0.113.9'], array_map(static fn ($d): ?string => $d->getIp(), $detections));
	}

	public function testAppsAreAllowedWhereThePolicyAllowsLoginsNothingConfirms(): void {
		$this->give(StepUpPolicy::BreachedPassword, $this->alice);
		$this->basicAuth($this->alice);
		$this->login($this->alice);
		$this->assertNull($this->stepUp());
		$this->assertTrue(Server::get(PasswordChangeFlag::class)->isRequired($this->alice->getUID()), 'Its next requests are refused by the forced password change');
	}

	public function testAnUnconfirmedLoginCannotComeBackThroughItsRememberMeCookie(): void {
		$this->give(StepUpPolicy::FlaggedSource, $this->alice);
		$this->startSession($this->alice);
		$this->login($this->alice);
		$this->assertNotNull($this->stepUp());
		$old = (string)$this->session->id;

		// The browser drops the session and comes back with the cookie: core renews the session.
		$this->session->clear();
		$this->session->id = bin2hex(random_bytes(32));
		$this->cookies['nc_session_id'] = $old;
		$this->method = 'GET';
		$this->listener()->handle(new UserLoggedInWithCookieEvent($this->alice, null));
		$this->assertSame(StepUpState::RESUMED, $this->stepUp()?->status);

		$block = $this->rule()->check($this->state, \OCA\IntrusionDetection\SessionState\RequestTarget::dav('PROPFIND', '/remote.php/dav/files/'));
		$this->assertNotNull($block);
		$this->assertNull($this->sessionUser, 'Ended');
		$failed = $this->detectionsOf(StepUpFailed::ID)[0];
		$this->assertSame(StepUpFailed::RULE_RESUMED, $failed->getExplanationData()['facts']['rule']);
		$this->assertNotContains('ban', array_column($failed->getActionList(), 'type'), 'Coming back is no reason to block the address');
		$this->assertSame(0, $this->unconfirmedRows());
	}

	public function testAnUnconfirmedLoginCannotComeBackFromItsSessionToken(): void {
		$this->give(StepUpPolicy::FlaggedSource, $this->alice);
		$token = $this->startSession($this->alice);
		$this->login($this->alice);

		// The PHP session data is gone, the session token is not: core logs in from the token.
		$this->session->clear();
		$this->session->id = $token['secret'];
		$this->method = 'GET';
		$this->login($this->alice, self::PASSWORD, tokenLogin: true);
		$this->assertSame(StepUpState::RESUMED, $this->stepUp()?->status);
	}

	public function testOtherRememberedLoginsAreLeftAlone(): void {
		$this->give(StepUpPolicy::FlaggedSource, $this->alice);
		$this->login($this->alice);
		$this->session->clear();
		$this->cookies['nc_session_id'] = 'a-session-that-was-confirmed';
		$this->listener()->handle(new UserLoggedInWithCookieEvent($this->alice, null));
		$this->assertNull($this->stepUp());
	}

	public function testDetectionsOfTheLoginAreLinkedToItsSessionAtTheFirstRequest(): void {
		$this->settings->setGlobal(StepUpPolicy::FlaggedSource->settingKey(), 'allow_notify');
		$bob = $this->user('ids-stepup-link', null);
		$this->give(StepUpPolicy::FlaggedSource, $bob);
		$token = $this->startSession($bob);
		$this->login($bob);
		$detection = $this->detectionsOf(StepUpUnconfirmed::ID)[0];

		$this->assertNull($this->rule()->check($this->state, \OCA\IntrusionDetection\SessionState\RequestTarget::dav('GET', '/')));
		$linked = Server::get(\OCA\IntrusionDetection\Db\DetectionMapper::class)->findById($detection->getId());
		$this->assertSame([$token['id']], $linked->getExplanationData()['facts'][LoginDetections::FACT]);
		$this->assertNull($this->state->get(SessionState::LOGIN_DETECTIONS), 'Once');
	}

	private function give(StepUpPolicy $policy, IUser $user): void {
		match ($policy) {
			StepUpPolicy::FlaggedSource => Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK),
			StepUpPolicy::SprayedPassword => array_map(
				static fn (string $fp) => Server::get(FlaggedSources::class)->flagPassword(bin2hex($fp)),
				Server::get(Fingerprinter::class)->passwordFlagFingerprints(self::PASSWORD),
			),
			StepUpPolicy::ProtectedAccount => Server::get(AccountProtection::class)->protect($user->getUID(), time() + 3600),
			StepUpPolicy::BreachedPassword => $this->breached($user),
			default => null,
		};
	}

	private function breached(IUser $user): void {
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode(BreachedPassword::ID), Mode::Protect->value);
		$userConfig = Server::get(IUserConfig::class);
		$userConfig->setValueBool($user->getUID(), Application::APP_ID, BreachedPasswordDetector::KEY_BREACHED, true, true);
		// Checked recently, so the login does not contact the breach list.
		$userConfig->setValueInt($user->getUID(), Application::APP_ID, BreachedPasswordDetector::KEY_CHECKED_AT, time(), true);
	}
}
