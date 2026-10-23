<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Authentication\Login\Chain;
use OC\Authentication\Login\LoginData;
use OC\User\Session;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailed;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused\StepUpRefused;
use OCA\IntrusionDetection\Check\Checks\StepUpRefusedClient\StepUpRefusedClient;
use OCA\IntrusionDetection\Check\Checks\StepUpUnconfirmed\StepUpUnconfirmed;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Confirm\LoginAssessment;
use OCA\IntrusionDetection\Confirm\LoginConfirmation;
use OCA\IntrusionDetection\Confirm\LoginConfirmations;
use OCA\IntrusionDetection\Confirm\NoMethodOutcome;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpReasons;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Login\LoginClassifier;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\LoginHistory\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\MailContent;
use OCA\IntrusionDetection\Notification\Mails;
use OCA\IntrusionDetection\Response\AccountProtection;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\Rules\StepUpRule;
use OCA\IntrusionDetection\Tests\BasicAuthServer;
use OCP\AppFramework\Controller;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * Real logins through core: the login form's login chain and Basic auth,
 * with the listeners the app registers itself. Credential headers a client
 * adds to the login form never make it look like an app. Only the request is
 * replaced, so that it looks like a browser posting the login form or an
 * app sending the password.
 */
#[Group('DB')]
class RealLoginTest extends IntegrationTestCase {
	use BasicAuthServer;

	private const PASSWORD = 'Correct-Horse-Battery-Staple-2026';

	private IUser $user;
	/** @var IRequest&MockObject */
	private IRequest $request;
	/** @var array<string, string> */
	private array $headers = [];
	private string $method = 'POST';
	private string $path = '/login';
	private string $remoteAddress = '198.51.100.9';
	/** @var array<string, string> */
	private array $cookies = [];
	/** @var list<array{string, MailContent}> */
	private array $mailed = [];

	protected function setUp(): void {
		parent::setUp();
		$user = Server::get(IUserManager::class)->createUser('ids-real-' . bin2hex(random_bytes(4)), self::PASSWORD);
		$this->assertInstanceOf(IUser::class, $user);
		$this->user = $user;
		$this->request = $this->createMock(IRequest::class);
		$this->request->method('getRemoteAddress')->willReturnCallback(fn (): string => $this->remoteAddress);
		$this->request->method('getHeader')->willReturnCallback(fn (string $name): string => $this->headers[$name] ?? '');
		$this->request->method('getMethod')->willReturnCallback(fn (): string => $this->method);
		$this->request->method('getPathInfo')->willReturnCallback(fn (): string => $this->path);
		$this->request->method('getCookie')->willReturnCallback(fn (string $name): ?string => $this->cookies[$name] ?? null);
		$this->overwriteService(IRequest::class, $this->request);
		// Services an earlier test may have built with its own request: rebuilt with this one.
		$addresses = new RemoteAddressResolver($this->request, Server::get(IThrottler::class), Server::get(ServerAddresses::class));
		$this->overwriteService(RemoteAddressResolver::class, $addresses);
		$this->overwriteService(LoginClassifier::class, new LoginClassifier($this->request, new RequestContext()));
		$this->overwriteService(LoginAssessment::class, new LoginAssessment(
			Server::get(Fingerprinter::class),
			Server::get(FlaggedSources::class),
			Server::get(StepUpReasons::class),
			Server::get(UnconfirmedSessions::class),
			Server::get(CoreSession::class),
			$this->request,
			\OC::$server->getRegisteredAppContainer(Application::APP_ID),
			Server::get(Caches::class),
			Server::get(LoggerInterface::class),
		));
		$mails = $this->createMock(Mails::class);
		$mails->method('send')->willReturnCallback(function (IUser $user, MailContent $content): bool {
			$this->mailed[] = [$user->getUID(), $content];
			return true;
		});
		$this->overwriteService(Mails::class, $mails);
		Server::get(AccountProtection::class)->protect($this->user->getUID(), time() + 3600);
		$this->settingsEditor()->setGlobal(StepUpPolicy::ProtectedAccount->settingKey(), NoMethodOutcome::Refuse->value);
	}

	protected function tearDown(): void {
		Server::get(Session::class)->logout();
		Server::get(ISession::class)->clear();
		$this->restoreService(IRequest::class);
		$this->restoreService(RemoteAddressResolver::class);
		$this->restoreService(LoginClassifier::class);
		$this->restoreService(LoginAssessment::class);
		$this->restoreService(Mails::class);
		$this->user->delete();
		parent::tearDown();
	}

	public function testLoginsWithThePasswordAreHeldBackThroughCore(): void {
		$result = Server::get(Chain::class)->process(new LoginData($this->request, $this->user->getUID(), self::PASSWORD, false));
		$this->assertTrue($result->isSuccess(), 'The password was right');

		$stepUp = StepUpState::fromArray(Server::get(SessionMarkers::class)->get(SessionMarkers::STEP_UP) ?? []);
		$this->assertNotNull($stepUp, 'The app\'s own listener marked the session');
		$this->assertSame(ConfirmationStatus::Refused, $stepUp->status, 'No email address and no second factor: refused, as configured');
		$this->assertSame(['protected_account'], $stepUp->policies);
		$this->assertCount(1, Server::get(DetectionMapper::class)->findList(new DetectionFilter(checkIds: [StepUpRefused::ID], uid: $this->user->getUID())));
		$history = Server::get(LoginHistoryMapper::class)->forUser($this->user->getUID(), 0);
		$this->assertCount(1, $history, 'The login is in the history, after the step-up decided');
		$this->assertSame([LoginHistory::METHOD_PASSWORD, LoginHistory::STEP_UP_REFUSED], [$history[0]->method, $history[0]->stepUp]);

		// The rest is in one test, because core keeps the app's listener, and with it the request
		// it was built with, for the whole run.
		// Forged credential headers on the login form change nothing.
		foreach (['Authorization' => 'Bearer x', 'PHP_AUTH_USER' => 'x'] as $header => $value) {
			Server::get(Session::class)->logout();
			Server::get(ISession::class)->clear();
			$this->headers = [$header => $value];
			$result = Server::get(Chain::class)->process(new LoginData($this->request, $this->user->getUID(), self::PASSWORD, false));
			$this->assertTrue($result->isSuccess());
			$stepUp = StepUpState::fromArray(Server::get(SessionMarkers::class)->get(SessionMarkers::STEP_UP) ?? []);
			$this->assertSame(ConfirmationStatus::Refused, $stepUp?->status, 'Held back like any login form, with ' . $header);
			$history = Server::get(LoginHistoryMapper::class)->forUser($this->user->getUID(), 0);
			$this->assertSame([LoginHistory::METHOD_PASSWORD, LoginHistory::STEP_UP_REFUSED], [$history[0]->method, $history[0]->stepUp]);
		}

		// The same account from an app that sends the password.
		Server::get(Session::class)->logout();
		Server::get(ISession::class)->clear();
		$this->headers = ['Authorization' => 'Basic ' . base64_encode($this->user->getUID() . ':' . self::PASSWORD)];
		$this->setBasicCredentials($this->user->getUID(), self::PASSWORD);
		$this->method = 'PROPFIND';
		$this->path = '/files/' . $this->user->getUID();
		$this->assertTrue(Server::get(Session::class)->logClientIn($this->user->getUID(), self::PASSWORD, $this->request, Server::get(IThrottler::class)));

		$stepUp = StepUpState::fromArray(Server::get(SessionMarkers::class)->get(SessionMarkers::STEP_UP) ?? []);
		$this->assertSame(ConfirmationStatus::RefusedClient, $stepUp?->status);
		$this->assertCount(1, Server::get(DetectionMapper::class)->findList(new DetectionFilter(checkIds: [StepUpRefusedClient::ID], uid: $this->user->getUID())));
		$history = Server::get(LoginHistoryMapper::class)->forUser($this->user->getUID(), 0);
		$this->assertCount(4, $history);
		$this->assertSame([LoginHistory::METHOD_CLIENT_PASSWORD, LoginHistory::STEP_UP_REFUSED], [$history[0]->method, $history[0]->stepUp]);

		// With an email address the account can confirm in a browser: its apps are refused even
		// where the setting would let a login in that nothing can confirm. Another address, so
		// that the decision about the app above is not repeated.
		$this->remoteAddress = '198.51.100.10';
		$this->settingsEditor()->setGlobal(StepUpPolicy::ProtectedAccount->settingKey(), NoMethodOutcome::AllowNotify->value);
		$this->user->setEMailAddress('real-login@example.com');
		Server::get(Session::class)->logout();
		Server::get(ISession::class)->clear();
		$this->assertTrue(Server::get(Session::class)->logClientIn($this->user->getUID(), self::PASSWORD, $this->request, Server::get(IThrottler::class)));
		$stepUp = StepUpState::fromArray(Server::get(SessionMarkers::class)->get(SessionMarkers::STEP_UP) ?? []);
		$this->assertSame(ConfirmationStatus::RefusedClient, $stepUp?->status, 'The password over Basic auth does not get around the email code');
		$this->assertSame([], Server::get(DetectionMapper::class)->findList(new DetectionFilter(checkIds: [StepUpUnconfirmed::ID], uid: $this->user->getUID())), 'Not let in unconfirmed');
		$this->assertSame([], $this->codeMails(), 'No code: an app cannot enter it');

		// A client with a cookie jar sends core's cookie test back from its second request on:
		// still an app. Nothing is started for it, nothing fails later, and nobody is told again.
		// The same address, decided afresh rather than repeated from the memory cache.
		Server::get(Caches::class)->clear();
		$this->settingsEditor()->setGlobal(GlobalSettings::STEP_UP_ADMIN_APPROVAL, true);
		$notices = $this->mailsOf('intrusion_detection.userNotice');
		Server::get(Session::class)->logout();
		Server::get(ISession::class)->clear();
		$this->cookies[LoginConfirmations::COOKIE_TEST] = 'test';
		$this->assertTrue(Server::get(Session::class)->logClientIn($this->user->getUID(), self::PASSWORD, $this->request, Server::get(IThrottler::class)));
		$stepUp = StepUpState::fromArray(Server::get(SessionMarkers::class)->get(SessionMarkers::STEP_UP) ?? []);
		$this->assertSame(ConfirmationStatus::RefusedClient, $stepUp?->status, 'Basic auth is an app whatever cookies it sends');
		$this->assertSame([], $this->codeMails(), 'No code');
		$this->assertSame(0, Server::get(ApprovalMapper::class)->countPendingFor(Approval::KIND_LOGIN, $this->user->getUID(), time()), 'No approval request');
		$this->assertSame([], Server::get(DetectionMapper::class)->findList(new DetectionFilter(checkIds: [StepUpFailed::ID], uid: $this->user->getUID())), 'Nothing waits that could fail');
		$this->assertSame($notices, $this->mailsOf('intrusion_detection.userNotice'), 'The user was told once today already');

		// From a network the account's apps synced from before, the app keeps working; its
		// session, a browser session because of the cookie test, serves apps only.
		Server::get(LoginHistoryMapper::class)->insert($this->user->getUID(), time() - 86400, SourceKey::fromIp('203.0.113.20'), 'DAVx5', LoginHistory::METHOD_CLIENT_PASSWORD, false, 'none', null, null);
		$this->remoteAddress = '203.0.113.21';
		Server::get(Session::class)->logout();
		Server::get(ISession::class)->clear();
		$this->assertTrue(Server::get(Session::class)->logClientIn($this->user->getUID(), self::PASSWORD, $this->request, Server::get(IThrottler::class)));
		$state = Server::get(SessionMarkers::class);
		$this->assertNull($state->get(SessionMarkers::STEP_UP), 'A protected account does not lock out its calendar app at home');
		$this->assertTrue($state->get(SessionMarkers::CONFIRMATION)[LoginConfirmation::CLIENT_ONLY] ?? false);
		$rule = Server::get(StepUpRule::class);
		$this->assertNull($rule->check($state, RequestTarget::dav('PROPFIND', '/remote.php/dav/files/' . $this->user->getUID())));
		$page = $rule->check($state, RequestTarget::app($this->createMock(Controller::class), 'index', 'GET', '/index.php/apps/files/'));
		$this->assertSame(StepUpRule::ERROR_CLIENT_ONLY, $page?->error, 'No pages from an app\'s session');
		$this->assertSame([], $this->codeMails());
	}

	/**
	 * @return int how many emails with this template were sent
	 */
	private function mailsOf(string $templateId): int {
		return count(array_filter($this->mailed, static fn (array $m): bool => $m[1]->templateId === $templateId));
	}

	/**
	 * @return list<string> the accounts that were sent a confirmation code
	 */
	private function codeMails(): array {
		$to = [];
		foreach ($this->mailed as [$uid, $mail]) {
			if ($mail->templateId === 'intrusion_detection.stepUpCode') {
				$to[] = $uid;
			}
		}
		return $to;
	}
}
