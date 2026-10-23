<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Confirm\Administrators;
use OCA\IntrusionDetection\Listener\AdminSessionsListener;
use OCA\IntrusionDetection\Listener\Login\AdminSessionStep;
use OCA\IntrusionDetection\Listener\Login\StepUpStep;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\Rules\AdminNetworkRule;
use OCA\IntrusionDetection\Tests\LoginSteps;
use OCP\Authentication\Token\IToken;
use OCP\Group\Events\UserAddedEvent;
use OCP\IGroupManager;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\Server;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use PHPUnit\Framework\Attributes\Group;

/**
 * "Administrators log in from trusted networks only" holds for the whole
 * session, not only at the password login: an administrator's session
 * that nothing but the network let in ends once it is used from outside
 * the trusted networks, also when it came back with its remember-me
 * cookie or the trusted networks changed. An account that becomes an
 * administrator logs in again.
 */
#[Group('DB')]
class AdminSessionNetworkTest extends StepUpTestCase {
	private const OFFICE = '192.0.2.0/24';
	private const INSIDE = '192.0.2.40';
	private const OUTSIDE = '203.0.113.9';

	private IUser $admin;

	protected function setUp(): void {
		parent::setUp();
		$this->admin = $this->user('ids-adminsession', 'admin@example.com');
		Server::get(IGroupManager::class)->get('admin')?->addUser($this->admin);
		$this->settingsEditor()->setGlobal(GlobalSettings::ADMIN_TRUSTED_NETWORKS_ONLY, true);
		$this->settingsEditor()->setGlobal(GlobalSettings::RISKY_NETWORK_OFFICE_NETWORKS, [self::OFFICE]);
		$this->remoteAddress = self::INSIDE;
	}

	public function testAnAdministratorSessionFromTheOfficeEndsOutsideIt(): void {
		$this->startSession($this->admin);
		$this->loginWithSteps(new UserLoggedInEvent($this->admin, $this->admin->getUID(), self::PASSWORD, false));
		$this->assertNull($this->adminRule()->check($this->state, $this->page()), 'Inside: nothing to do');

		$this->remoteAddress = self::OUTSIDE;
		$block = $this->adminRule()->check($this->state, $this->page());

		$this->assertNotNull($block);
		$this->assertNull($this->sessionUser, 'The session ends; the next login from here must confirm');
	}

	public function testARememberedLoginFromOutsideEnds(): void {
		$this->remoteAddress = self::OUTSIDE;
		$this->startSession($this->admin);
		$this->loginWithSteps(new UserLoggedInWithCookieEvent($this->admin, null));

		$this->assertNotNull($this->adminRule()->check($this->state, $this->page()));
		$this->assertNull($this->sessionUser);
	}

	public function testALoginConfirmedOutsideMayMove(): void {
		$this->remoteAddress = self::OUTSIDE;
		$this->startSession($this->admin);
		$this->loginWithSteps(new UserLoggedInEvent($this->admin, $this->admin->getUID(), self::PASSWORD, false));
		$this->verifyController()->confirm('482915');
		$this->assertNull($this->stepUp(), 'Confirmed with the emailed code');

		$this->remoteAddress = '198.51.100.20';
		$this->assertNull($this->adminRule()->check($this->state, $this->page()));
		$this->assertNotNull($this->sessionUser);
	}

	public function testALoginThatWaitsOutsideReachesItsConfirmation(): void {
		$this->remoteAddress = self::OUTSIDE;
		$this->startSession($this->admin);
		$this->loginWithSteps(new UserLoggedInEvent($this->admin, $this->admin->getUID(), self::PASSWORD, false));
		$this->assertNotNull($this->stepUp(), 'The login waits for its confirmation');

		$this->assertNull($this->adminRule()->check($this->state, $this->page()), 'The step-up rule decides about a waiting login');
		$this->assertNotNull($this->sessionUser, 'The session waits for its code');

		$this->verifyController()->confirm('482915');
		$this->assertNull($this->stepUp());
		$this->assertNull($this->adminRule()->check($this->state, $this->page()));
	}

	public function testRemovingTheNetworkEndsTheSessionsItLetIn(): void {
		$this->startSession($this->admin);
		$this->loginWithSteps(new UserLoggedInEvent($this->admin, $this->admin->getUID(), self::PASSWORD, false));

		$this->settingsEditor()->setGlobal(GlobalSettings::RISKY_NETWORK_OFFICE_NETWORKS, ['198.51.100.0/24']);

		$this->assertNotNull($this->adminRule()->check($this->state, $this->page()));
		$this->assertNull($this->sessionUser);
	}

	public function testOtherAccountsAndTheSwitchOffChangeNothing(): void {
		$bob = $this->user('ids-adminsession-user', 'bob@example.com');
		$this->startSession($bob);
		$this->loginWithSteps(new UserLoggedInEvent($bob, $bob->getUID(), self::PASSWORD, false));
		$this->assertNull($this->state->get(SessionMarkers::ADMIN_SESSION));

		$this->session->clear();
		$this->startSession($this->admin);
		$this->loginWithSteps(new UserLoggedInEvent($this->admin, $this->admin->getUID(), self::PASSWORD, false));
		$this->settingsEditor()->setGlobal(GlobalSettings::ADMIN_TRUSTED_NETWORKS_ONLY, false);
		$this->remoteAddress = self::OUTSIDE;
		$this->assertNull($this->adminRule()->check($this->state, $this->page()));
		$this->assertNotNull($this->sessionUser);
	}

	public function testAnAccountMadeAdministratorLogsInAgain(): void {
		$carol = $this->user('ids-adminsession-new', 'carol@example.com');
		$browser = $this->token($carol, IToken::TEMPORARY_TOKEN, 'Firefox on Linux');
		$app = $this->token($carol, IToken::PERMANENT_TOKEN, 'Calendar app');
		$admin = Server::get(IGroupManager::class)->get('admin');
		$this->assertNotNull($admin);
		$admin->addUser($carol);

		$this->sessionsListener()->handle(new UserAddedEvent($admin, $carol));

		$this->assertFalse($this->tokenExists($browser['id']), 'Its browser sessions were let in as an ordinary account\'s');
		$this->assertTrue($this->tokenExists($app['id']), 'App passwords are not affected by the rule');
	}

	public function testWithTheSwitchOffBecomingAnAdministratorEndsNothing(): void {
		$this->settingsEditor()->setGlobal(GlobalSettings::ADMIN_TRUSTED_NETWORKS_ONLY, false);
		$carol = $this->user('ids-adminsession-off', 'carol@example.com');
		$browser = $this->token($carol, IToken::TEMPORARY_TOKEN, 'Firefox on Linux');
		$admin = Server::get(IGroupManager::class)->get('admin');
		$this->assertNotNull($admin);
		$admin->addUser($carol);

		$this->sessionsListener()->handle(new UserAddedEvent($admin, $carol));

		$this->assertTrue($this->tokenExists($browser['id']));
	}

	private function loginWithSteps(UserLoggedInEvent|UserLoggedInWithCookieEvent $event): void {
		$steps = [
			StepUpStep::class => new StepUpStep($this->assessment()),
			AdminSessionStep::class => new AdminSessionStep($this->state, Server::get(Administrators::class)),
		];
		LoginSteps::listener($steps, $this->appSettings(), $this->request, new RequestContext(), $this->addresses())->handle($event);
	}

	private function adminRule(): AdminNetworkRule {
		return new AdminNetworkRule($this->appSettings(), $this->addresses(), $this->userSession, Server::get(IURLGenerator::class), Server::get(AuditLogger::class));
	}

	private function sessionsListener(): AdminSessionsListener {
		return Server::get(AdminSessionsListener::class);
	}

	private function page(): RequestTarget {
		return RequestTarget::dav('PROPFIND', '/remote.php/dav/files/');
	}
}
