<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Controller;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Controller\DigestApiController;
use OCA\IntrusionDetection\Controller\EventsApiController;
use OCA\IntrusionDetection\Event\EventExamples;
use OCA\IntrusionDetection\Notification\DigestSender;
use OCP\App\IAppManager;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\AuthorizedAdminSetting;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\SubAdminRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class DigestApiControllerTest extends TestCase {
	use AnswersLikeTheApi;

	private DigestSender&MockObject $sender;
	private AuditLogger&MockObject $audit;
	private IUserSession&MockObject $userSession;
	private IL10N $l;

	protected function setUp(): void {
		parent::setUp();
		$this->sender = $this->createMock(DigestSender::class);
		$this->audit = $this->createMock(AuditLogger::class);
		$this->userSession = $this->createMock(IUserSession::class);
		$this->l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
	}

	public function testBothApisAreForAdministratorsOnly(): void {
		foreach ([DigestApiController::class, EventsApiController::class] as $controller) {
			$class = new \ReflectionClass($controller);
			$this->assertSame(OpenAPI::SCOPE_ADMINISTRATION, $class->getAttributes(OpenAPI::class)[0]->getArguments()['scope']);
			foreach ($class->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
				if ($method->getAttributes(ApiRoute::class) === []) {
					continue;
				}
				$this->assertStringStartsWith('/api/v1/', $method->getAttributes(ApiRoute::class)[0]->getArguments()['url']);
				foreach ([NoAdminRequired::class, SubAdminRequired::class, PublicPage::class, AuthorizedAdminSetting::class, NoCSRFRequired::class] as $forbidden) {
					$this->assertSame([], $method->getAttributes($forbidden), $method->getName() . ' must not carry ' . $forbidden);
				}
				$write = $method->getAttributes(ApiRoute::class)[0]->getArguments()['verb'] !== 'GET';
				$this->assertSame($write ? 1 : 0, count($method->getAttributes(PasswordConfirmationRequired::class)), $method->getName());
			}
		}
		$rateLimit = (new \ReflectionMethod(DigestApiController::class, 'sendTest'))->getAttributes(UserRateLimit::class);
		$this->assertCount(1, $rateLimit, 'every test digest is an email');
	}

	public function testTheTestDigestGoesToTheActingAdminAndIsAudited(): void {
		$admin = $this->user('alice', 'alice@example.com');
		$this->userSession->method('getUser')->willReturn($admin);
		$this->sender->expects($this->once())->method('sendTest')->with($admin)->willReturn(DigestSender::TEST_SENT);
		$this->audit->expects($this->once())->method('log')->with('test digest sent to %s', ['actor' => 'alice']);
		$response = $this->controller()->sendTest();
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame(['message' => 'The test digest was sent to alice@example.com.'], $response->getData());
	}

	public function testWithoutAnAddressOrAWorkingMailServerItExplainsWhy(): void {
		$this->userSession->method('getUser')->willReturn($this->user('bob', null));
		$this->sender->method('sendTest')->willReturnOnConsecutiveCalls(DigestSender::TEST_NO_ADDRESS, DigestSender::TEST_FAILED);
		$this->audit->expects($this->never())->method('log');
		$first = $this->controller()->sendTest();
		$this->assertSame(Http::STATUS_BAD_REQUEST, $first->getStatus());
		$this->assertSame('no_address', $first->getData()['reason']);
		$second = $this->controller()->sendTest();
		$this->assertSame('send_failed', $second->getData()['reason']);
	}

	public function testTheOverviewIsForTheViewer(): void {
		$admin = $this->user('alice', 'alice@example.com');
		$this->userSession->method('getUser')->willReturn($admin);
		$this->sender->expects($this->once())->method('overview')->with($admin)->willReturn(['frequency' => 'weekly']);
		$this->assertSame(['frequency' => 'weekly'], $this->answer(fn () => $this->controller()->digest())->getData());
	}

	public function testTheEventsFollowTheAddressSetting(): void {
		$settings = $this->createMock(AppSettings::class);
		$settings->method('eventsIncludeIp')->willReturn(false);
		$apps = $this->createMock(IAppManager::class);
		$apps->method('isEnabledForAnyone')->with('webhook_listeners')->willReturn(true);
		$examples = $this->createMock(EventExamples::class);
		$examples->method('all')->willReturn([]);
		$controller = new EventsApiController($this->createMock(IRequest::class), $this->l, $this->userSession, $examples, $settings, $apps);
		$this->assertSame(['includeIp' => false, 'webhooksEnabled' => true, 'events' => []], $controller->events()->getData());
	}

	private function controller(): DigestApiController {
		return new DigestApiController($this->createMock(IRequest::class), $this->l, $this->userSession, $this->sender, $this->audit);
	}

	private function user(string $uid, ?string $email): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($uid);
		$user->method('getEMailAddress')->willReturn($email);
		return $user;
	}
}
