<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Middleware;

use OC\Session\Memory;
use OCA\IntrusionDetection\Dav\SessionStatePlugin;
use OCA\IntrusionDetection\Middleware\SessionBlockedException;
use OCA\IntrusionDetection\Middleware\SessionStateMiddleware;
use OCA\IntrusionDetection\Sensitive\SensitiveActions;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\SessionState\SessionStateRules;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\OCSController;
use OCP\IRequest;
use OCP\IUserSession;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Sabre\DAV\Exception\Forbidden;
use Sabre\HTTP\RequestInterface;
use Sabre\HTTP\Response;
use Test\TestCase;

/**
 * A sensitive action that needs confirmation is answered with 403 and the
 * URL of the confirm page: JSON for scripts, OCS data for OCS (v1 and v2),
 * a redirect for a browser opening a page or submitting a form, and a
 * header for WebDAV. A refused new device during lockdown is answered the
 * same way, with its message.
 */
class ConfirmationAnswerTest extends TestCase {
	private const URL = '/index.php/apps/intrusion_detection/confirm?redirect_url=%2Findex.php%2Fsettings%2Fuser%2Fsecurity';
	private const DIALOG = ['title' => 'Confirm it\'s you', 'text' => 'To do this, confirm it\'s you.', 'confirm' => 'Confirm', 'cancel' => 'Cancel'];

	private string $method = 'POST';
	/** @var array<string, string> */
	private array $headers = ['Accept' => 'application/json, text/plain, */*', 'X-Requested-With' => 'XMLHttpRequest'];
	private ?string $format = null;
	private SessionBlock $block;

	protected function setUp(): void {
		parent::setUp();
		$this->block = SessionBlock::confirmationRequired(self::URL, 'To do this, confirm it\'s you.', self::DIALOG);
	}

	public function testAScriptGetsJsonWithTheUrlAndTheDialogsTexts(): void {
		$response = $this->answer($this->createMock(Controller::class));
		$this->assertInstanceOf(JSONResponse::class, $response);
		$this->assertSame(Http::STATUS_FORBIDDEN, $response->getStatus());
		$this->assertSame([
			'error' => 'confirmation_required',
			'url' => self::URL,
			'message' => 'To do this, confirm it\'s you.',
			'dialog' => self::DIALOG,
		], $response->getData());
	}

	/**
	 * @return array<string, array{int, int, int}>
	 */
	public static function ocsVersions(): array {
		return [
			'OCS v2' => [2, Http::STATUS_FORBIDDEN, Http::STATUS_FORBIDDEN],
			'OCS v1' => [1, Http::STATUS_OK, Http::STATUS_FORBIDDEN],
		];
	}

	#[DataProvider('ocsVersions')]
	public function testOcsGetsTheErrorAndUrlAsData(int $version, int $httpStatus, int $ocsStatus): void {
		$this->format = 'json';
		$this->headers['OCS-APIREQUEST'] = 'true';
		$controller = new class('provisioning_api', $this->request()) extends OCSController {
		};
		$controller->setOCSVersion($version);
		$response = $this->answer($controller);
		$this->assertSame($httpStatus, $response->getStatus());
		$body = json_decode($response->render(), true);
		$this->assertSame($ocsStatus, $body['ocs']['meta']['statuscode']);
		$this->assertSame('confirmation_required', $body['ocs']['data']['error']);
		$this->assertSame(self::URL, $body['ocs']['data']['url']);
		$this->assertSame(self::DIALOG, $body['ocs']['data']['dialog']);
	}

	public function testABrowserOpeningAPageIsSentToTheConfirmPage(): void {
		$this->method = 'GET';
		$this->headers = ['Accept' => 'text/html,application/xhtml+xml'];
		$response = $this->answer($this->createMock(Controller::class));
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertSame(self::URL, $response->getRedirectURL());
	}

	public function testABrowserSubmittingAFormIsSentToTheConfirmPage(): void {
		$this->headers = ['Accept' => 'text/html,application/xhtml+xml'];
		$response = $this->answer($this->createMock(Controller::class));
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertSame(Http::STATUS_SEE_OTHER, $response->getStatus(), 'The browser opens the confirm page with GET');
	}

	public function testOtherBlocksKeepTheirAnswers(): void {
		$this->block = new SessionBlock('step_up_required', 'X-Nextcloud-Step-Up', 'Confirm the login', '/verify');
		$this->headers = ['Accept' => 'text/html'];
		$response = $this->answer($this->createMock(Controller::class));
		$this->assertInstanceOf(JSONResponse::class, $response, 'A submitted form of a pending login gets 403 as before');
		$this->assertSame(['error' => 'step_up_required'], $response->getData());
	}

	public function testANewDeviceDuringLockdownIsRefusedWithItsMessage(): void {
		$this->block = SessionBlock::refused(SensitiveActions::ERROR_DEVICES_LOCKED, SensitiveActions::LOCKDOWN_HEADER, 'New devices cannot be connected right now. Please try again later.', '/index.php/apps/intrusion_detection/confirm/unavailable');
		$response = $this->answer($this->createMock(Controller::class));
		$this->assertSame(Http::STATUS_FORBIDDEN, $response->getStatus());
		$this->assertSame(['error' => 'devices_locked', 'message' => 'New devices cannot be connected right now. Please try again later.'], $response->getData());

		$this->headers = ['Accept' => 'text/html'];
		$page = $this->answer($this->createMock(Controller::class));
		$this->assertInstanceOf(RedirectResponse::class, $page, 'The grant page of a client login submits a form');
		$this->assertSame('/index.php/apps/intrusion_detection/confirm/unavailable', $page->getRedirectURL());
	}

	public function testWebDavGetsAForbiddenWithAHeader(): void {
		$userSession = $this->createMock(IUserSession::class);
		$userSession->method('isLoggedIn')->willReturn(true);
		$plugin = new SessionStatePlugin($this->rules(), new SessionState(new Memory(), $this->createMock(LoggerInterface::class)), $userSession, $this->createMock(LoggerInterface::class));
		$request = $this->createMock(RequestInterface::class);
		$request->method('getMethod')->willReturn('PUT');
		$request->method('getUrl')->willReturn('/remote.php/dav/files/alice/a.txt');
		$response = new Response();
		try {
			$plugin->beforeMethod($request, $response);
			$this->fail('The request is refused');
		} catch (Forbidden $e) {
			$this->assertSame('This action needs a fresh confirmation. Confirm it in a browser, then try again.', $e->getMessage());
		}
		$this->assertSame('required', $response->getHeader('X-Nextcloud-Confirmation'));
	}

	private function answer(Controller $controller): \OCP\AppFramework\Http\Response {
		$middleware = new SessionStateMiddleware(
			$this->rules(),
			new SessionState(new Memory(), $this->createMock(LoggerInterface::class)),
			$this->loggedIn(),
			$this->request(),
			$this->createMock(LoggerInterface::class),
		);
		try {
			$middleware->beforeController($controller, 'create');
			$this->fail('The rule blocks');
		} catch (SessionBlockedException $e) {
			return $middleware->afterException($controller, 'create', $e);
		}
	}

	private function rules(): SessionStateRules {
		$rule = new class($this) implements ISessionStateRule {
			public function __construct(
				private readonly ConfirmationAnswerTest $test,
			) {
			}

			public function check(SessionState $state, RequestTarget $target): ?SessionBlock {
				return $this->test->block();
			}
		};
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturn($rule);
		return new class($container, $this->createMock(LoggerInterface::class)) extends SessionStateRules {
			protected function classes(): array {
				return [ISessionStateRule::class];
			}
		};
	}

	public function block(): SessionBlock {
		return $this->block;
	}

	private function loggedIn(): IUserSession {
		$userSession = $this->createMock(IUserSession::class);
		$userSession->method('isLoggedIn')->willReturn(true);
		return $userSession;
	}

	private function request(): IRequest {
		$request = $this->createMock(IRequest::class);
		$request->method('getMethod')->willReturnCallback(fn (): string => $this->method);
		$request->method('getRequestUri')->willReturn('/index.php/settings/personal/authtokens');
		$request->method('getHeader')->willReturnCallback(fn (string $name): string => $this->headers[$name] ?? '');
		$request->method('getFormat')->willReturnCallback(fn (): ?string => $this->format);
		return $request;
	}
}
