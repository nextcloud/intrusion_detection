<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\SessionState;

use OC\Core\Controller\LoginController;
use OC\Core\Controller\TwoFactorChallengeController;
use OCA\IntrusionDetection\Controller\PasswordChangeController;
use OCA\IntrusionDetection\Response\PasswordChangeFlag;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\Rules\PasswordChangeRule;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\DataResponse;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserSession;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class PasswordChangeRuleTest extends TestCase {
	/** @var array<string, mixed> */
	private array $sessionData = [];
	private SessionState $state;
	/** @var PasswordChangeFlag&MockObject */
	private PasswordChangeFlag $flag;
	private PasswordChangeRule $rule;
	private bool $required = true;

	protected function setUp(): void {
		parent::setUp();
		$session = $this->createMock(ISession::class);
		$session->method('get')->willReturnCallback(fn (string $key): mixed => $this->sessionData[$key] ?? null);
		$session->method('set')->willReturnCallback(function (string $key, mixed $value): void {
			$this->sessionData[$key] = $value;
		});
		$session->method('remove')->willReturnCallback(function (string $key): void {
			unset($this->sessionData[$key]);
		});
		$this->state = new SessionState($session, $this->createMock(LoggerInterface::class));
		$this->flag = $this->createMock(PasswordChangeFlag::class);
		$this->flag->method('isRequired')->willReturnCallback(fn (): bool => $this->required);
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$userSession = $this->createMock(IUserSession::class);
		$userSession->method('getUser')->willReturn($user);
		$urls = $this->createMock(IURLGenerator::class);
		$urls->method('linkToRoute')->willReturnCallback(static fn (string $route, array $params): string => '/index.php/apps/intrusion_detection/password?redirect_url=' . rawurlencode((string)$params['redirect_url']));
		$this->rule = new PasswordChangeRule($this->flag, $userSession, $urls);
	}

	public function testNothingHappensWithoutAMarkerAndNothingIsRead(): void {
		$this->flag->expects($this->never())->method('isRequired');
		$this->assertNull($this->rule->check($this->state, $this->app(new SomeController(), 'index')));
		$this->assertNull($this->rule->check($this->state, RequestTarget::dav('PROPFIND', '/remote.php/dav/files/alice/')));
	}

	public function testABrowserIsSentToThePasswordPage(): void {
		$this->mark(PasswordChangeRule::MODE_REDIRECT);
		$block = $this->rule->check($this->state, $this->app(new SomeController(), 'index'));
		$this->assertNotNull($block);
		$this->assertSame('password_change_required', $block->error);
		$this->assertSame('/index.php/apps/intrusion_detection/password?redirect_url=%2Findex.php%2Fapps%2Ffiles%2F', $block->redirectUrl);
	}

	public function testAppsAndScriptsAreRefused(): void {
		$this->mark(PasswordChangeRule::MODE_REFUSE);
		$block = $this->rule->check($this->state, $this->app(new SomeController(), 'index'));
		$this->assertNotNull($block);
		$this->assertNull($block->redirectUrl, 'Nothing to redirect to: they cannot open a page');
	}

	public function testWebDavIsRefusedWithAHeader(): void {
		$this->mark(PasswordChangeRule::MODE_REDIRECT);
		$block = $this->rule->check($this->state, RequestTarget::dav('PROPFIND', '/remote.php/dav/files/alice/'));
		$this->assertNotNull($block);
		$this->assertSame('X-Nextcloud-Password-Change', $block->davHeader);
	}

	public function testThePasswordPageLogoutTheSecondFactorAndPublicResourcesStayReachable(): void {
		$this->mark(PasswordChangeRule::MODE_REDIRECT);
		$this->assertNull($this->rule->check($this->state, $this->app($this->createMock(PasswordChangeController::class), 'show')));
		$this->assertNull($this->rule->check($this->state, $this->app($this->createMock(LoginController::class), 'logout')));
		$this->assertNull($this->rule->check($this->state, $this->app($this->createMock(TwoFactorChallengeController::class), 'showChallenge')));
		$this->assertNull($this->rule->check($this->state, $this->app(new SomeController(), 'publicStyle')));
		$this->assertNotNull($this->rule->check($this->state, $this->app(new SomeController(), 'publicStyle', 'POST')), 'Only reading public resources');
		$this->assertNotNull($this->rule->check($this->state, $this->app($this->createMock(LoginController::class), 'showLoginForm')));
	}

	public function testAMarkerWhoseRequirementWasLiftedIsDropped(): void {
		$this->mark(PasswordChangeRule::MODE_REDIRECT);
		$this->required = false;
		$this->assertNull($this->rule->check($this->state, $this->app(new SomeController(), 'index')));
		$this->assertTrue($this->state->isEmpty());
	}

	public function testAMarkerOfAnotherAccountIsDropped(): void {
		$this->state->set(SessionState::PASSWORD_CHANGE, ['uid' => 'bob', 'mode' => PasswordChangeRule::MODE_REDIRECT]);
		$this->assertNull($this->rule->check($this->state, $this->app(new SomeController(), 'index')));
		$this->assertTrue($this->state->isEmpty());
	}

	private function mark(string $mode): void {
		$this->state->set(SessionState::PASSWORD_CHANGE, ['uid' => 'alice', 'mode' => $mode, 'since' => 1]);
	}

	private function app(Controller $controller, string $method, string $httpMethod = 'GET'): RequestTarget {
		return RequestTarget::app($controller, $method, $httpMethod, '/index.php/apps/files/');
	}
}

class SomeController extends Controller {
	public function __construct() {
		parent::__construct('files', \OCP\Server::get(IRequest::class));
	}

	public function index(): DataResponse {
		return new DataResponse();
	}

	#[PublicPage]
	public function publicStyle(): DataResponse {
		return new DataResponse();
	}
}
