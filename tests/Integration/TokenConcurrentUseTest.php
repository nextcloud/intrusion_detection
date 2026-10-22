<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialTracker;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialUse;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialUseResolver;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\Requirement;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Explain\CheckPresenter;
use OCA\IntrusionDetection\Explain\IAsksWasThisYou;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\SessionState\Rules\CredentialUseRule;
use OCA\IntrusionDetection\SessionState\SessionStateRules;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Token\IToken;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IAppConfig;
use OCP\IConfig;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Concept section 10.12 end to end: a credential that is used from two
 * networks at the same time is reported once it logs in, for app passwords
 * over Basic and Bearer, the login password over Basic and browser sessions.
 */
#[Group('DB')]
class TokenConcurrentUseTest extends CredentialUseTestCase {
	/** A browser session is named after the user agent it logged in with */
	private const FIREFOX = 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0';

	public function testAStolenAppPasswordUsedAlongsideItsOwnerIsReported(): void {
		$user = $this->newUser('ids-cu', 'cu@example.com');
		$token = $this->token($user, IToken::PERMANENT_TOKEN, 'Desktop client on laptop');
		$login = $this->appPasswordLogin($user, $token);

		$this->send(self::HOME, $this->basic($user->getUID(), $token['secret']), [], $login);
		$this->send(self::AWAY, $this->basic($user->getUID(), $token['secret']), [], $login);
		$this->send(self::HOME, $this->basic($user->getUID(), $token['secret']), [], $login);
		$this->assertSame([], $this->detectionsOf(TokenConcurrentUse::ID), 'Two switches are not enough');
		$this->send(self::AWAY, $this->basic($user->getUID(), $token['secret']), [], $login);

		$detection = $this->only();
		$this->assertSame($user->getUID(), $detection->getUid());
		$this->assertSame(self::AWAY, $detection->getIp());
		$this->assertSame('medium', $detection->getSeverity());
		$this->assertTrue($detection->isEnforced());
		$facts = $detection->getExplanationData()['facts'];
		$this->assertSame(TokenConcurrentUse::KIND_APP_PASSWORD, $facts['kind']);
		$this->assertSame('basic', $facts['scheme']);
		$this->assertSame([self::HOME, self::AWAY, 3, 4], [$facts['ip1'], $facts['ip2'], $facts['switches'], $facts['family']]);
		$this->assertSame('Desktop client on laptop', $facts['tokenName']);
		$this->assertSame($token['id'], $facts['tokenId']);
		$this->assertSame(['window' => 900, 'min_switches' => 3], $detection->getExplanationData()['thresholds']);

		$actions = array_column($detection->getActionList(), 'enforced', 'type');
		$this->assertSame([ResponseType::NotifyAdmin->value => true, ResponseType::NotifyUser->value => true], $actions, 'By default: tell the user and the admins, revoke nothing');
		$this->assertTrue($this->tokenExists($token['id']));
		$this->assertCount(1, $this->notificationsFor($user->getUID()));
		$this->sendQueuedMails();
		$this->assertCount(1, $this->mailed);
		$mail = json_encode(get_object_vars($this->mailed[0][1]), JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
		$this->assertStringContainsString('Your app password \\"Desktop client on laptop\\" was used from two different networks at the same time: ' . self::HOME . ' and ' . self::AWAY, $mail, 'The name the user gave it');
		$this->assertSame([[$user->getUID(), $detection->getId()]], $this->forgotten, 'The known device that came with it is forgotten');
	}

	public function testTheAppPasswordCanBeRevokedAtOnce(): void {
		$this->settings->setResponses(TokenConcurrentUse::ID, [ResponseType::RevokeToken, ResponseType::NotifyUser]);
		$user = $this->newUser('ids-cu', 'cu@example.com');
		$token = $this->token($user, IToken::PERMANENT_TOKEN, 'Phone');
		$child = $this->token($user, IToken::PERMANENT_TOKEN, 'Created with the phone');
		Server::get(TokenOriginMapper::class)->record($child['id'], $user->getUID(), self::AWAY, $token['id'], time());
		$other = $this->token($user, IToken::PERMANENT_TOKEN, 'Laptop');

		$this->pingPong($this->basic($user->getUID(), $token['secret']), [], $this->appPasswordLogin($user, $token));

		$detection = $this->only();
		$this->assertFalse($this->tokenExists($token['id']), 'Revoked');
		$this->assertFalse($this->tokenExists($child['id']), 'With what was created with it');
		$this->assertTrue($this->tokenExists($other['id']), 'The other devices keep working');
		$message = Server::get(UserMessages::class)->build($detection, $user, 'en');
		$this->assertContains('The app password "Phone" was revoked.', $message->done, 'The name the user gave it');
	}

	public function testABearerTokenIsTheSameCredentialAsWithBasic(): void {
		$user = $this->newUser('ids-cu');
		$token = $this->token($user, IToken::PERMANENT_TOKEN, 'Sync client');
		$login = $this->appPasswordLogin($user, $token);
		$bearer = ['HTTP_AUTHORIZATION' => 'Bearer ' . $token['secret']];

		$this->send(self::HOME, $this->basic($user->getUID(), $token['secret']), [], $login);
		$this->send(self::AWAY, $bearer, [], $login);
		$this->send(self::HOME, $this->basic($user->getUID(), $token['secret']), [], $login);
		$this->send(self::AWAY, $bearer, [], $login);

		$facts = $this->only()->getExplanationData()['facts'];
		$this->assertSame(TokenConcurrentUse::KIND_APP_PASSWORD, $facts['kind']);
		$this->assertSame('bearer', $facts['scheme']);
		$this->assertSame($token['id'], $facts['tokenId']);
	}

	public function testABrowserSessionUsedFromTwoNetworksIsReportedAndCanBeEnded(): void {
		$this->settings->setResponses(TokenConcurrentUse::ID, [ResponseType::RevokeToken, ResponseType::NotifyUser]);
		$user = $this->newUser('ids-cu', 'cu@example.com');
		$session = $this->token($user, IToken::TEMPORARY_TOKEN, self::FIREFOX);

		$this->pingPong([], [$this->cookieName => $session['secret']], $this->loggedInSession($user, $session));

		$detection = $this->only();
		$facts = $detection->getExplanationData()['facts'];
		$this->assertSame(TokenConcurrentUse::KIND_SESSION, $facts['kind']);
		$this->assertSame([$session['id'], $session['id']], [$facts['tokenId'], $facts['sessionTokenId']]);
		$this->assertSame(self::FIREFOX, $facts['tokenName']);
		$this->assertFalse($this->tokenExists($session['id']), 'The session is ended');
		$message = Server::get(UserMessages::class)->build($detection, $user, 'en');
		$this->assertContains('The session (Firefox on Linux) was ended.', $message->done);
		$this->assertStringContainsString('Your logged-in session (Firefox on Linux) was used from two different networks at the same time', implode(' ', $message->happened));
		$narrative = json_encode(Server::get(NarrativeBuilder::class)->build($detection, Server::get(IFactory::class)->get(Application::APP_ID, 'en'))->toArray(), JSON_UNESCAPED_UNICODE);
		$this->assertStringContainsString('Ended the session \"' . str_replace('/', '\/', self::FIREFOX) . '\"', (string)$narrative, 'Administrators see the name as it was sent');
	}

	public function testThePasswordOverBasicIsConfirmedByTheLogin(): void {
		$user = $this->newUser('ids-cu');
		$password = 'A-long-test-password-' . $user->getUID();

		// No controller and no WebDAV: decided at the login event and at the end of the request.
		$this->pingPong($this->basic($user->getUID(), $password), [], $this->passwordLogin($user), rule: false);

		$detection = $this->only();
		$facts = $detection->getExplanationData()['facts'];
		$this->assertSame(TokenConcurrentUse::KIND_PASSWORD, $facts['kind']);
		$this->assertNull($facts['tokenId']);
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$this->assertStringContainsString('The password of the account ' . $user->getUID() . ' was sent by an app from two different networks', Server::get(CheckRegistry::class)->check(TokenConcurrentUse::class)->narrative($detection, $l)[0]);
	}

	public function testACredentialThatNeverLogsInNeverBecomesADetection(): void {
		$user = $this->newUser('ids-cu');
		$this->pingPong($this->basic($user->getUID(), 'a-guessed-password'), [], null);
		$this->assertSame([], $this->detectionsOf(TokenConcurrentUse::ID), 'Not logged in');
		$this->assertSame([], $this->cachedKeys(), 'Nor written to the cache');

		// The session logged in with another app password than the one sent.
		$token = $this->token($user, IToken::PERMANENT_TOKEN, 'Real one');
		$other = $this->token($user, IToken::PERMANENT_TOKEN, 'Other');
		$this->now += 3600;
		$this->pingPong($this->basic($user->getUID(), $token['secret']), [], $this->appPasswordLogin($user, $other));
		$this->assertSame([], $this->detectionsOf(TokenConcurrentUse::ID), 'The credential sent is not the one that logged in');
	}

	public function testAStolenSessionCannotHideBehindAMadeUpHeader(): void {
		$user = $this->newUser('ids-cu');
		$session = $this->token($user, IToken::TEMPORARY_TOKEN, self::FIREFOX);
		$cookie = [$this->cookieName => $session['secret']];
		$owner = $this->loggedInSession($user, $session);
		$garbage = $this->basic($user->getUID(), 'made-up');

		$this->send(self::HOME, [], $cookie, $owner);
		$this->send(self::AWAY, $garbage, $cookie, $owner);
		$this->send(self::HOME, [], $cookie, $owner);
		$this->assertSame([], $this->detectionsOf(TokenConcurrentUse::ID));
		$context = $this->send(self::AWAY, $garbage, $cookie, $owner);

		$facts = $this->only()->getExplanationData()['facts'];
		$this->assertSame(TokenConcurrentUse::KIND_SESSION, $facts['kind']);
		$this->assertSame($session['id'], $facts['sessionTokenId']);
		$use = $context->get(CredentialUseResolver::CONTEXT_KEY);
		$this->assertInstanceOf(CredentialUse::class, $use);
		$this->assertTrue($use->resolved);
	}

	public function testAClientSendingItsAppPasswordWithTheSessionCookieCostsNoSecondLookup(): void {
		$user = $this->newUser('ids-cu');
		$token = $this->token($user, IToken::PERMANENT_TOKEN, 'Desktop client');
		$sessionId = bin2hex(random_bytes(16));
		$reused = function (TestSession $session) use ($user, $token, $sessionId) {
			$session->id = $sessionId;
			$session->set('token-id', $token['id']);
			$session->set('app_password', $token['secret']);
			return $user;
		};
		$this->send(self::HOME, $this->basic($user->getUID(), $token['secret']), [$this->cookieName => $sessionId], $reused);
		$entries = $this->cachedKeys();
		$this->assertCount(1, $entries, 'Only the app password is tracked, not the cookie as well');
		$context = $this->send(self::HOME, $this->basic($user->getUID(), $token['secret']), [$this->cookieName => $sessionId], $reused);
		$use = $context->get(CredentialUseResolver::CONTEXT_KEY);
		$this->assertTrue($use instanceof CredentialUse && $use->resolved);
		$this->assertSame($entries, $this->cachedKeys());
	}

	public function testObserveRecordsWhatWouldHaveBeenDone(): void {
		$this->settings->setMode(TokenConcurrentUse::ID, Mode::Observe);
		$this->settings->setResponses(TokenConcurrentUse::ID, [ResponseType::RevokeToken, ResponseType::NotifyAdmin, ResponseType::NotifyUser]);
		$user = $this->newUser('ids-cu', 'cu@example.com');
		$token = $this->token($user, IToken::PERMANENT_TOKEN, 'Phone');
		$this->pingPong($this->basic($user->getUID(), $token['secret']), [], $this->appPasswordLogin($user, $token));

		$detection = $this->only();
		$this->assertFalse($detection->isEnforced());
		$this->assertSame([false, false, false], array_values(array_column($detection->getActionList(), 'enforced')));
		$this->assertTrue($this->tokenExists($token['id']));
		$this->assertSame([], $this->notificationsFor($user->getUID()));
		$this->assertSame([], $this->mailed);
		$this->assertSame([], $this->forgotten);
	}

	public function testOffAndLearningMode(): void {
		$user = $this->newUser('ids-cu');
		$token = $this->token($user, IToken::PERMANENT_TOKEN, 'Phone');
		$this->settings->setMode(TokenConcurrentUse::ID, Mode::Off);
		$this->pingPong($this->basic($user->getUID(), $token['secret']), [], $this->appPasswordLogin($user, $token));
		$this->assertSame([], $this->detectionsOf(TokenConcurrentUse::ID));
		$this->assertSame([], $this->cachedKeys(), 'Off: nothing is tracked');

		$this->settings->setMode(TokenConcurrentUse::ID, Mode::Protect);
		Server::get(IAppConfig::class)->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);
		$this->pingPong($this->basic($user->getUID(), $token['secret']), [], $this->appPasswordLogin($user, $token));
		$detection = $this->only();
		$this->assertFalse($detection->isEnforced(), 'Learning mode observes');
		$this->assertSame(ModeState::REASON_LEARNING, $detection->getExplanationData()['mode']['reason']);
	}

	public function testRepeatedSwitchesOfOneTokenAreOneDetectionPerHour(): void {
		$user = $this->newUser('ids-cu');
		$token = $this->token($user, IToken::PERMANENT_TOKEN, 'Phone');
		$login = $this->appPasswordLogin($user, $token);
		$this->pingPong($this->basic($user->getUID(), $token['secret']), [], $login);
		for ($i = 0; $i < 6; $i++) {
			$this->send($i % 2 === 0 ? self::HOME : self::AWAY, $this->basic($user->getUID(), $token['secret']), [], $login);
		}
		$this->assertSame(1, $this->only()->getHits(), 'Fires at most once per window');
		$this->now += 900;
		$this->pingPong($this->basic($user->getUID(), $token['secret']), [], $login);
		$this->assertSame(2, $this->only()->getHits(), 'Merged into the detection of the same token');
		$this->assertCount(1, $this->notificationsFor($user->getUID()), 'Told once per hour');
	}

	public function testUnavailableWithoutAMemoryCache(): void {
		$settings = new Settings(
			Server::get(IAppConfig::class),
			Server::get(CheckRegistry::class),
			Server::get(ITimeFactory::class),
			new Prerequisites($this->cacheFactory(null), Server::get(IConfig::class)),
			Server::get(GlobalSettings::class),
			Server::get(IEventDispatcher::class),
		);
		$state = $settings->modeState(TokenConcurrentUse::ID);
		$this->assertSame(Mode::Protect, $state->configured);
		$this->assertSame(Mode::Off, $state->effective);
		$this->assertSame(ModeState::REASON_REQUIREMENT, $state->reason);
		$this->assertSame(Requirement::MemoryCache, $state->missing);
		try {
			$settings->setMode(TokenConcurrentUse::ID, Mode::Observe);
			$this->fail('Cannot be switched on');
		} catch (InvalidParamException $e) {
			$this->assertSame('mode_unavailable', $e->reason);
			$this->assertSame(['why' => 'memory_cache'], $e->details);
		}
		$presented = (new CheckPresenter($settings, new Prerequisites($this->cacheFactory(null), Server::get(IConfig::class)), Server::get(TextRenderer::class)))
			->present(Server::get(CheckRegistry::class)->get(TokenConcurrentUse::ID), Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		$this->assertSame([['id' => 'memory_cache', 'met' => false, 'text' => Requirement::MemoryCache->describe(Server::get(IFactory::class)->get(Application::APP_ID, 'en'))]], $presented['requirements']);
		$this->assertStringContainsString('With APCu only, each web server sees only its own requests', $presented['cost']['text']);

		$this->tracker = new CredentialTracker($this->cacheFactory(null), $settings);
		$user = $this->newUser('ids-cu');
		$token = $this->token($user, IToken::PERMANENT_TOKEN, 'Phone');
		$context = $this->send(self::HOME, $this->basic($user->getUID(), $token['secret']), [], $this->appPasswordLogin($user, $token));
		$this->assertNull($context->get(CredentialUseResolver::CONTEXT_KEY), 'The guard did nothing');
	}

	public function testTheCheckAsksWasThisYouAndResolvesInTheSessionRules(): void {
		$check = Server::get(CheckRegistry::class)->check(TokenConcurrentUse::class);
		$this->assertInstanceOf(IAsksWasThisYou::class, $check);
		$this->assertTrue($check->asksWasThisYou(new Detection()));
		$this->assertContains(CredentialUseRule::class, SessionStateRules::RULES);
		$this->assertGreaterThan(Server::get(CheckRegistry::class)->get(TokenConcurrentUse::ID)->param(TokenConcurrentUse::PARAM_WINDOW)->max, CredentialTracker::TTL, 'Entries outlive the longest window');
	}

	/**
	 * A, B, A, B: the fourth request fires.
	 *
	 * @param array<string, string> $server
	 * @param array<string, string> $cookies
	 */
	private function pingPong(array $server, array $cookies, ?\Closure $authenticate, bool $rule = true): void {
		foreach ([self::HOME, self::AWAY, self::HOME, self::AWAY] as $ip) {
			$this->send($ip, $server, $cookies, $authenticate, $rule);
		}
	}

	private function only(): Detection {
		$detections = Server::get(DetectionMapper::class)->findList(new DetectionFilter(checkIds: [TokenConcurrentUse::ID]));
		$this->assertCount(1, $detections);
		return $detections[0];
	}

	/**
	 * @return list<string>
	 */
	private function cachedKeys(): array {
		$keys = [];
		foreach ((new \ReflectionProperty($this->cache, 'cachedData'))->getValue($this->cache) as $key => $value) {
			$keys[] = (string)$key;
		}
		return $keys;
	}

	private function detectionsOf(string $checkId): array {
		return Server::get(DetectionMapper::class)->findList(new DetectionFilter(checkIds: [$checkId]));
	}
}
