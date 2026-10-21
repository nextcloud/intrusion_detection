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
use OCA\IntrusionDetection\Check\Checks\StepUpRefused;
use OCA\IntrusionDetection\Check\Checks\StepUpRefusedClient;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Response\AccountProtection;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\Tests\BasicAuthServer;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\MockObject;

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

	protected function setUp(): void {
		parent::setUp();
		$user = Server::get(IUserManager::class)->createUser('ids-real-' . bin2hex(random_bytes(4)), self::PASSWORD);
		$this->assertInstanceOf(IUser::class, $user);
		$this->user = $user;
		$this->request = $this->createMock(IRequest::class);
		$this->request->method('getRemoteAddress')->willReturn('198.51.100.9');
		$this->request->method('getHeader')->willReturnCallback(fn (string $name): string => $this->headers[$name] ?? '');
		$this->request->method('getMethod')->willReturnCallback(fn (): string => $this->method);
		$this->request->method('getPathInfo')->willReturnCallback(fn (): string => $this->path);
		$this->overwriteService(IRequest::class, $this->request);
		Server::get(AccountProtection::class)->protect($this->user->getUID(), time() + 3600);
	}

	protected function tearDown(): void {
		Server::get(Session::class)->logout();
		Server::get(ISession::class)->clear();
		$this->restoreService(IRequest::class);
		$this->user->delete();
		parent::tearDown();
	}

	public function testLoginsWithThePasswordAreHeldBackThroughCore(): void {
		$result = Server::get(Chain::class)->process(new LoginData($this->request, $this->user->getUID(), self::PASSWORD, false));
		$this->assertTrue($result->isSuccess(), 'The password was right');

		$stepUp = StepUpState::fromArray(Server::get(SessionState::class)->get(SessionState::STEP_UP) ?? []);
		$this->assertNotNull($stepUp, 'The app\'s own listener marked the session');
		$this->assertSame(StepUpState::REFUSED, $stepUp->status, 'No email address and no second factor: refused by default');
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
			$stepUp = StepUpState::fromArray(Server::get(SessionState::class)->get(SessionState::STEP_UP) ?? []);
			$this->assertSame(StepUpState::REFUSED, $stepUp?->status, 'Held back like any login form, with ' . $header);
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

		$stepUp = StepUpState::fromArray(Server::get(SessionState::class)->get(SessionState::STEP_UP) ?? []);
		$this->assertSame(StepUpState::REFUSED_CLIENT, $stepUp?->status);
		$this->assertCount(1, Server::get(DetectionMapper::class)->findList(new DetectionFilter(checkIds: [StepUpRefusedClient::ID], uid: $this->user->getUID())));
		$history = Server::get(LoginHistoryMapper::class)->forUser($this->user->getUID(), 0);
		$this->assertCount(4, $history);
		$this->assertSame([LoginHistory::METHOD_CLIENT_PASSWORD, LoginHistory::STEP_UP_REFUSED], [$history[0]->method, $history[0]->stepUp]);
	}
}
