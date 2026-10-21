<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\BackgroundJob\Cleanup;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Listener\LoginHistoryListener;
use OCA\IntrusionDetection\Login\InteractiveLogin;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\LoginHistory\LoginHistoryEntry;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\LoginNotices;
use OCA\IntrusionDetection\Privacy\UserDataCleanup;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\Rules\LoginHistoryRule;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengePassed;
use OCP\ICacheFactory;
use OCP\IUser;
use OCP\Server;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * The login history (concept section 7): one row per successful login of
 * each kind, how it was confirmed, the session it created, the limits for
 * apps that log in with every request, the reads and the retention.
 */
#[Group('DB')]
class LoginHistoryTest extends StepUpTestCase {
	private IUser $alice;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-history', 'alice@example.com');
		$this->headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0';
	}

	public function testALoginThroughTheFormIsOneRowLinkedToItsSessionOnTheFirstRequest(): void {
		$token = $this->startSession($this->alice);
		$this->loginAndRecord($this->alice);
		$rows = $this->historyOf($this->alice);
		$this->assertCount(1, $rows);
		$this->assertSame(LoginHistory::METHOD_PASSWORD, $rows[0]->method);
		$this->assertSame('none', $rows[0]->confirmedBy);
		$this->assertNull($rows[0]->stepUp, 'Nothing extra was needed');
		$this->assertSame($this->remoteAddress, $rows[0]->ip);
		$this->assertSame(SourceKey::fromIp($this->remoteAddress)->netKey, $rows[0]->netKey);
		$this->assertSame('Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0', $rows[0]->userAgent);
		$this->assertFalse($rows[0]->knownDevice);
		$this->assertNull($rows[0]->sessionTokenId, 'Core creates the session token after the login');

		$this->historyRule()->check($this->state, RequestTarget::dav('PROPFIND', '/'));
		$this->assertSame($token['id'], $this->historyOf($this->alice)[0]->sessionTokenId);
		$this->assertTrue($this->state->get(SessionState::LOGIN_HISTORY)['linked'] ?? false, 'Linked once');
	}

	public function testTheRowSaysHowALoginThatNeededConfirmationWasConfirmed(): void {
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK);
		$this->startSession($this->alice);
		$this->loginAndRecord($this->alice);
		$this->assertSame([LoginHistory::STEP_UP_PENDING, 'none'], $this->outcome($this->alice));

		$this->verifyController()->confirm('482915');
		$this->assertSame([LoginHistory::STEP_UP_CONFIRMED, 'email_code'], $this->outcome($this->alice));

		$this->session->clear();
		$this->startSession($this->alice);
		$this->loginAndRecord($this->alice);
		for ($i = 0; $i < 5; $i++) {
			$this->verifyController()->confirm('111111');
		}
		$this->assertSame([LoginHistory::STEP_UP_FAILED, 'none'], $this->outcome($this->alice));
	}

	public function testRefusedAndAllowedLoginsWithoutAWayToConfirm(): void {
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK);
		$bob = $this->user('ids-history-bob', null);
		$this->startSession($bob);
		$this->loginAndRecord($bob);
		$this->assertSame([LoginHistory::STEP_UP_REFUSED, 'none'], $this->outcome($bob));

		$this->settings->setGlobal(StepUpPolicy::FlaggedSource->settingKey(), 'allow_notify');
		$this->session->clear();
		$this->startSession($bob);
		$this->loginAndRecord($bob);
		$this->assertSame([LoginHistory::STEP_UP_ALLOWED, 'none'], $this->outcome($bob));
	}

	public function testALoginFromAKnownDevice(): void {
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK);
		$this->startSession($this->alice);
		$this->loginAndRecord($this->alice);
		$this->verifyController()->confirm('482915', '', '1');

		$this->session->clear();
		$this->nextRequest();
		$this->startSession($this->alice);
		$this->loginAndRecord($this->alice);
		$row = $this->historyOf($this->alice)[0];
		$this->assertTrue($row->knownDevice);
		$this->assertSame('known_device', $row->confirmedBy);
		$this->assertSame(LoginHistory::STEP_UP_CONFIRMED, $row->stepUp);
	}

	public function testASecondFactorAtLoginIsNoted(): void {
		$this->startSession($this->alice);
		$this->loginAndRecord($this->alice);
		$this->historyListener()->handle(new TwoFactorProviderChallengePassed($this->alice, $this->createMock(IProvider::class)));
		$this->assertSame([null, 'second_factor'], $this->outcome($this->alice));
	}

	public function testAppsThatSendThePasswordAreRecordedOnceADayPerAddressWithoutAMemoryCache(): void {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn(false);
		$history = new LoginHistory(Server::get(LoginHistoryMapper::class), $this->state, $this->session, $this->currentSession, $factory, Server::get(ITimeFactory::class));
		$this->basicAuth($this->alice);
		for ($i = 0; $i < 3; $i++) {
			$this->session->clear();
			$this->session->id = bin2hex(random_bytes(16));
			$this->login($this->alice);
			$this->historyListener($history)->handle(new UserLoggedInEvent($this->alice, $this->alice->getUID(), self::PASSWORD, false));
		}
		$rows = $this->historyOf($this->alice);
		$this->assertCount(1, $rows);
		$this->assertSame(LoginHistory::METHOD_CLIENT_PASSWORD, $rows[0]->method);

		$this->remoteAddress = '198.51.100.99';
		$this->historyListener($history)->handle(new UserLoggedInEvent($this->alice, $this->alice->getUID(), self::PASSWORD, false));
		$this->assertCount(2, $this->historyOf($this->alice), 'Another address is another row');
	}

	public function testAppPasswordsAreRecordedOncePerTokenAndHourWithAMemoryCache(): void {
		$cache = new ArrayCache();
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn(true);
		$factory->method('createDistributed')->willReturn($cache);
		$history = new LoginHistory(Server::get(LoginHistoryMapper::class), $this->state, $this->session, $this->currentSession, $factory, Server::get(ITimeFactory::class));
		$first = $this->token($this->alice, \OCP\Authentication\Token\IToken::PERMANENT_TOKEN, 'Desktop client');
		$second = $this->token($this->alice, \OCP\Authentication\Token\IToken::PERMANENT_TOKEN, 'Phone');
		$this->headers['Authorization'] = 'Basic ' . base64_encode('alice:app-password');
		$this->setBasicCredentials('alice', 'app-password');
		$this->method = 'PROPFIND';
		$this->pathInfo = '/files/alice';
		foreach ([$first, $first, $second, $first] as $token) {
			$this->session->clear();
			$this->session->set('token-id', $token['id']);
			$this->historyListener($history)->handle(new UserLoggedInEvent($this->alice, 'alice', 'app-password', true));
		}
		$rows = $this->historyOf($this->alice);
		$this->assertCount(2, $rows, 'Once per app password');
		$this->assertSame([LoginHistory::METHOD_APP_PASSWORD, LoginHistory::METHOD_APP_PASSWORD], array_map(static fn (LoginHistoryEntry $e): string => $e->method, $rows));
		$this->assertEqualsCanonicalizing([$first['id'], $second['id']], array_map(static fn (LoginHistoryEntry $e): ?int => $e->sessionTokenId, $rows));
	}

	public function testOtherKindsOfLogin(): void {
		$this->headers['Authorization'] = 'Bearer some-token';
		$this->method = 'GET';
		$this->pathInfo = '/cloud/user';
		$this->historyListener()->handle(new UserLoggedInEvent($this->alice, 'alice', '', true));
		unset($this->headers['Authorization']);
		$this->historyListener()->handle(new UserLoggedInWithCookieEvent($this->alice, 'alice', null));
		$this->historyListener()->handle(new UserLoggedInEvent($this->alice, 'alice', '', false));
		$this->historyListener()->handle(new UserLoggedInEvent($this->alice, 'alice', '', true));
		$this->assertSame(
			[LoginHistory::METHOD_SSO, LoginHistory::METHOD_COOKIE, LoginHistory::METHOD_TOKEN],
			array_map(static fn (LoginHistoryEntry $e): string => $e->method, $this->historyOf($this->alice)),
			'A session restored from its token is no new login',
		);
	}

	public function testUserAgentsAreCleanedAndCut(): void {
		$this->headers['User-Agent'] = "Evil\x00Agent\r\n" . str_repeat('x', 400);
		$this->startSession($this->alice);
		$this->loginAndRecord($this->alice);
		$agent = (string)$this->historyOf($this->alice)[0]->userAgent;
		$this->assertSame(200, mb_strlen($agent));
		$this->assertStringStartsWith('Evil Agent x', $agent);
	}

	public function testTheHistoryIsReadByAccountOrAddressWithinARange(): void {
		$mapper = Server::get(LoginHistoryMapper::class);
		$now = time();
		$other = $this->user('ids-history-other', null);
		$mapper->insert($this->alice->getUID(), $now - 7200, SourceKey::fromIp('203.0.113.5'), null, LoginHistory::METHOD_PASSWORD, false, 'none', null, null);
		$mapper->insert($this->alice->getUID(), $now - 3600, SourceKey::fromIp('203.0.113.6'), null, LoginHistory::METHOD_PASSWORD, false, 'none', null, null);
		$mapper->insert($other->getUID(), $now - 1800, SourceKey::fromIp('203.0.113.5'), null, LoginHistory::METHOD_SSO, false, 'none', null, null);
		$mapper->insert($this->alice->getUID(), $now - 86400 * 40, SourceKey::fromIp('203.0.113.5'), null, LoginHistory::METHOD_PASSWORD, false, 'none', null, null);

		$this->assertCount(2, $mapper->forUser($this->alice->getUID(), $now - 86400));
		$this->assertCount(1, $mapper->forUser($this->alice->getUID(), $now - 86400, $now - 3600), 'Until is exclusive');
		$this->assertCount(1, $mapper->forUser($this->alice->getUID(), 0, null, 1), 'The limit');
		$this->assertCount(3, $mapper->forUser($this->alice->getUID(), 0));
		$this->assertCount(2, $mapper->forAddress('203.0.113.5', $now - 86400), 'Both accounts from the address');
		$this->assertCount(3, $mapper->forAddress('203.0.113.0/24', $now - 86400), 'The whole network');

		$this->settings->setGlobal(GlobalSettings::HISTORY_RETENTION_DAYS, 30);
		$this->invokePrivate(Server::get(Cleanup::class), 'run', [null]);
		$this->assertCount(2, $mapper->forUser($this->alice->getUID(), 0), 'Older than the retention: deleted');

		Server::get(UserDataCleanup::class)->deleteUser($this->alice->getUID());
		$this->assertCount(0, $mapper->forUser($this->alice->getUID(), 0));
		$this->assertCount(1, $mapper->forUser($other->getUID(), 0));
	}

	private function loginAndRecord(IUser $user): void {
		$this->login($user);
		$this->historyListener()->handle(new UserLoggedInEvent($user, $user->getUID(), self::PASSWORD, false));
	}

	/**
	 * @return list<LoginHistoryEntry> newest first
	 */
	private function historyOf(IUser $user): array {
		return Server::get(LoginHistoryMapper::class)->forUser($user->getUID(), 0);
	}

	/**
	 * @return array{?string, string} the step-up and how the newest login was confirmed
	 */
	private function outcome(IUser $user): array {
		$row = $this->historyOf($user)[0];
		return [$row->stepUp, $row->confirmedBy];
	}

	private function historyListener(?LoginHistory $history = null): LoginHistoryListener {
		return new LoginHistoryListener(
			$this->settings,
			new InteractiveLogin($this->request),
			$this->addresses(),
			$this->request,
			new OverridingContainer([
				LoginHistory::class => $history ?? $this->history(),
				KnownDevices::class => $this->knownDevices(),
				LoginNotices::class => $this->createMock(LoginNotices::class),
			]),
			Server::get(LoggerInterface::class),
		);
	}

	private function historyRule(): LoginHistoryRule {
		return new LoginHistoryRule($this->userSession, new OverridingContainer([LoginHistory::class => $this->history()]), Server::get(LoggerInterface::class));
	}
}
