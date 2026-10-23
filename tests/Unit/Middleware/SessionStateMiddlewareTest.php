<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Middleware;

use OCA\IntrusionDetection\Dav\SessionStatePlugin;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Middleware\SessionBlockedException;
use OCA\IntrusionDetection\Middleware\SessionStateMiddleware;
use OCA\IntrusionDetection\Response\PasswordChangeFlag;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\Rules\CredentialUseRule;
use OCA\IntrusionDetection\SessionState\Rules\PasswordChangeRule;
use OCA\IntrusionDetection\SessionState\Rules\StepUpRule;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionGate;
use OCA\IntrusionDetection\SessionState\SessionStateRules;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\OCSController;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserSession;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Sabre\DAV\Exception\Forbidden;
use Sabre\HTTP\RequestInterface;
use Sabre\HTTP\Response;
use Test\TestCase;

/**
 * The session-state middleware and WebDAV plugin: what they answer, and
 * that a session with nothing pending costs one session read per rule.
 */
class SessionStateMiddlewareTest extends TestCase {
	/** @var array<string, mixed> */
	private array $sessionData = [];
	private int $sessionReads = 0;
	/** @var IRequest&MockObject */
	private IRequest $request;
	/** @var PasswordChangeFlag&MockObject */
	private PasswordChangeFlag $flag;
	private bool $loggedIn = true;
	private string $accept = 'text/html,application/xhtml+xml';
	private string $method = 'GET';
	private SessionMarkers $state;
	private SessionStateRules $rules;
	private IUserSession $userSession;

	protected function setUp(): void {
		parent::setUp();
		$session = $this->createMock(ISession::class);
		$session->method('get')->willReturnCallback(function (string $key): mixed {
			$this->sessionReads++;
			return $this->sessionData[$key] ?? null;
		});
		$session->method('set')->willReturnCallback(function (string $key, mixed $value): void {
			$this->sessionData[$key] = $value;
		});
		$this->state = new SessionMarkers($session, $this->createMock(LoggerInterface::class));
		$this->flag = $this->createMock(PasswordChangeFlag::class);
		$this->flag->method('isRequired')->willReturn(true);
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$userSession = $this->createMock(IUserSession::class);
		$userSession->method('getUser')->willReturnCallback(fn (): ?IUser => $this->loggedIn ? $user : null);
		$userSession->method('isLoggedIn')->willReturnCallback(fn (): bool => $this->loggedIn);
		$this->userSession = $userSession;
		$urls = $this->createMock(IURLGenerator::class);
		$urls->method('linkToRoute')->willReturn('/index.php/apps/intrusion_detection/password?redirect_url=%2Fapps%2Ffiles%2F');
		$rule = new PasswordChangeRule($this->flag, $userSession, $urls);
		$container = $this->createMock(ContainerInterface::class);
		$credentialRule = new CredentialUseRule(new RequestContext(), $this->createMock(ContainerInterface::class));
		$stepUp = new StepUpRule($userSession, $urls, $this->createMock(ITimeFactory::class), $container, $this->createMock(LoggerInterface::class));
		$container->method('get')->willReturnCallback(static fn (string $id): object => match ($id) {
			StepUpRule::class => $stepUp,
			CredentialUseRule::class => $credentialRule,
			default => $rule,
		});
		$this->rules = new SessionStateRules($container, $this->createMock(LoggerInterface::class), new \OCA\IntrusionDetection\Login\RequestContext(), $this->createMock(\OCP\IRequest::class));
		$this->request = $this->createMock(IRequest::class);
		$this->request->method('getMethod')->willReturnCallback(fn (): string => $this->method);
		$this->request->method('getRequestUri')->willReturn('/apps/files/');
		$this->request->method('getHeader')->willReturnCallback(fn (string $name): string => $name === 'Accept' ? $this->accept : '');
	}

	public function testNothingPendingCostsOneSessionReadPerRuleAndNoDatabase(): void {
		$this->flag->expects($this->never())->method('isRequired');
		$middleware = $this->middleware();
		$controller = $this->controller();
		$start = hrtime(true);
		for ($i = 0; $i < 1000; $i++) {
			$middleware->beforeController($controller, 'index');
		}
		$elapsed = (hrtime(true) - $start) / 1e6;
		$this->assertLessThanOrEqual(1000 * count(SessionStateRules::RULES), $this->sessionReads, 'At most one session read per rule and request');
		$this->assertLessThan(500, $elapsed, 'Far below a millisecond per request');
	}

	public function testRequestsOfVisitorsAreNotLookedAt(): void {
		$this->loggedIn = false;
		$this->middleware()->beforeController($this->controller(), 'index');
		$this->assertSame(0, $this->sessionReads);
	}

	public function testABrowserIsRedirected(): void {
		$this->mark(PasswordChangeRule::MODE_REDIRECT);
		$response = $this->blockedResponse($this->controller());
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertSame('/index.php/apps/intrusion_detection/password?redirect_url=%2Fapps%2Ffiles%2F', $response->getRedirectURL());
	}

	public function testScriptsGetForbiddenWithTheReason(): void {
		$this->mark(PasswordChangeRule::MODE_REDIRECT);
		$this->accept = 'application/json';
		$response = $this->blockedResponse($this->controller());
		$this->assertInstanceOf(JSONResponse::class, $response);
		$this->assertSame(403, $response->getStatus());
		$this->assertSame(['error' => 'password_change_required'], $response->getData());

		$this->accept = 'text/html';
		$this->method = 'POST';
		$this->assertInstanceOf(JSONResponse::class, $this->blockedResponse($this->controller()), 'A form post is not a page load');
	}

	public function testOcsRequestsGetTheReasonAsTheEnvelopeMessage(): void {
		$this->mark(PasswordChangeRule::MODE_REDIRECT);
		$controller = new class('files', $this->request) extends OCSController {
			public function index(): DataResponse {
				return new DataResponse();
			}
		};
		$response = $this->blockedResponse($controller);
		$this->assertInstanceOf(JSONResponse::class, $response);
		$this->assertSame(403, $response->getStatus());
		$this->assertSame(['message' => 'password_change_required'], $response->getData(), 'Core\'s OCS middleware puts the message into the envelope');
	}

	public function testRefusedSessionsAreNotRedirectedEvenInABrowser(): void {
		$this->mark(PasswordChangeRule::MODE_REFUSE);
		$this->assertInstanceOf(JSONResponse::class, $this->blockedResponse($this->controller()));
	}

	public function testAFailingRuleLetsTheRequestPassAndTheFirstBlockingRuleDecides(): void {
		$broken = $this->createMock(ISessionStateRule::class);
		$broken->method('check')->willThrowException(new \RuntimeException('broken'));
		$passing = $this->createMock(ISessionStateRule::class);
		$passing->method('check')->willReturn(null);
		$blocking = $this->createMock(ISessionStateRule::class);
		$blocking->method('check')->willReturn(new SessionBlock('second', 'X-Second', 'second'));
		$later = $this->createMock(ISessionStateRule::class);
		$later->expects($this->never())->method('check');

		$this->assertNull($this->registry([$broken, $passing])->check($this->state, RequestTarget::dav('GET', '/')), 'A broken rule fails open');
		$this->assertSame('second', $this->registry([$broken, $passing, $blocking, $later])->check($this->state, RequestTarget::dav('GET', '/'))?->error);
	}

	public function testWebDavGetsForbiddenWithAHeader(): void {
		$this->mark(PasswordChangeRule::MODE_REDIRECT);
		$plugin = new SessionStatePlugin(new SessionGate($this->rules, $this->state, $this->userSession, $this->request, $this->createMock(LoggerInterface::class)));
		$request = $this->createMock(RequestInterface::class);
		$request->method('getMethod')->willReturn('PROPFIND');
		$request->method('getUrl')->willReturn('/remote.php/dav/files/alice/');
		$response = new Response();
		try {
			$plugin->beforeMethod($request, $response);
			$this->fail('The request must be refused');
		} catch (Forbidden $e) {
			$this->assertSame(Forbidden::class, $e::class, 'Exactly Sabre\'s Forbidden, which the DAV app logs at debug level');
			$this->assertSame(403, $e->getHTTPCode());
			$this->assertSame('required', $response->getHeader('X-Nextcloud-Password-Change'));
		}
	}

	public function testWebDavWithNothingPendingPasses(): void {
		$plugin = new SessionStatePlugin(new SessionGate($this->rules, $this->state, $this->userSession, $this->request, $this->createMock(LoggerInterface::class)));
		$request = $this->createMock(RequestInterface::class);
		$request->method('getMethod')->willReturn('PROPFIND');
		$request->method('getUrl')->willReturn('/remote.php/dav/files/alice/');
		$response = new Response();
		$plugin->beforeMethod($request, $response);
		$this->assertLessThanOrEqual(count(SessionStateRules::RULES), $this->sessionReads);
		$this->assertNull($response->getHeader('X-Nextcloud-Password-Change'));
	}

	/**
	 * @param list<ISessionStateRule> $rules
	 */
	private function registry(array $rules): SessionStateRules {
		$byClass = [];
		foreach ($rules as $i => $rule) {
			$byClass['rule' . $i] = $rule;
		}
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $id): object => $byClass[$id]);
		return new class(array_keys($byClass), $container, $this->createMock(LoggerInterface::class), new \OCA\IntrusionDetection\Login\RequestContext(), $this->createMock(\OCP\IRequest::class)) extends SessionStateRules {
			/**
			 * @param list<string> $names
			 */
			public function __construct(
				private readonly array $names,
				ContainerInterface $container,
				LoggerInterface $logger,
				\OCA\IntrusionDetection\Login\RequestContext $context,
				\OCP\IRequest $request,
			) {
				parent::__construct($container, $logger, $context, $request);
			}

			protected function classes(): array {
				/** @var list<class-string<ISessionStateRule>> */
				return $this->names;
			}
		};
	}

	private function mark(string $mode): void {
		$this->sessionData[SessionMarkers::SESSION_KEY] = [SessionMarkers::PASSWORD_CHANGE => ['uid' => 'alice', 'mode' => $mode, 'since' => 1]];
	}

	private function blockedResponse(Controller $controller): \OCP\AppFramework\Http\Response {
		$middleware = $this->middleware();
		try {
			$middleware->beforeController($controller, 'index');
		} catch (SessionBlockedException $e) {
			return $middleware->afterException($controller, 'index', $e);
		}
		$this->fail('The request must be blocked');
	}

	private function middleware(): SessionStateMiddleware {
		return new SessionStateMiddleware(new SessionGate($this->rules, $this->state, $this->userSession, $this->request, $this->createMock(LoggerInterface::class)), $this->request);
	}

	private function controller(): Controller {
		return new class('files', $this->request) extends Controller {
			public function index(): DataResponse {
				return new DataResponse();
			}
		};
	}
}
