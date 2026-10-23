<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\SessionState;

use OC\Core\Controller\LoginController;
use OC\Core\Controller\TwoFactorChallengeController;
use OCA\IntrusionDetection\Controller\NoticeController;
use OCA\IntrusionDetection\Controller\PasswordChangeController;
use OCA\IntrusionDetection\Controller\VerifyController;
use OCA\IntrusionDetection\SessionState\LoginFlowRoute;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCP\AppFramework\Controller;
use OCP\AppFramework\OCSController;
use OCP\Authentication\TwoFactorAuth\ALoginSetupController;
use OCP\IRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

/**
 * The pages of the login flow by their route, and what counts as a
 * browser loading a page.
 */
class RequestTargetTest extends TestCase {
	/**
	 * @return array<string, array{class-string<Controller>, string, ?LoginFlowRoute}>
	 */
	public static function targets(): array {
		return [
			'verify page' => [VerifyController::class, 'show', LoginFlowRoute::Verify],
			'verify action' => [VerifyController::class, 'confirm', LoginFlowRoute::Verify],
			'password page' => [PasswordChangeController::class, 'show', LoginFlowRoute::PasswordChange],
			'security notice' => [NoticeController::class, 'show', LoginFlowRoute::Notice],
			'second-factor challenge' => [TwoFactorChallengeController::class, 'showChallenge', LoginFlowRoute::SecondFactorChallenge],
			'second-factor setup' => [ALoginSetupController::class, 'setup', LoginFlowRoute::SecondFactorSetup],
			'log out' => [LoginController::class, 'logout', LoginFlowRoute::Logout],
			'login form' => [LoginController::class, 'showLoginForm', null],
			'OCS' => [OCSController::class, 'index', null],
			'any other page' => [Controller::class, 'index', null],
		];
	}

	#[DataProvider('targets')]
	public function testTheLoginFlowPagesAreKnownByTheirRoute(string $class, string $method, ?LoginFlowRoute $route): void {
		$target = $this->target($class, $method);
		$this->assertSame($route, $target->route());
		$this->assertSame($route !== null, $route !== null && $target->isRoute($route));
		$this->assertSame($class === OCSController::class, $target->isOcs());
		$this->assertNull(RequestTarget::dav('PROPFIND', '/remote.php/dav/files/alice/')->route());
	}

	public function testOnlyABrowserReadingAPageNavigates(): void {
		$this->assertTrue($this->target(Controller::class, 'index')->isPageNavigation($this->request('text/html', '')));
		$this->assertFalse($this->target(Controller::class, 'index')->isPageNavigation($this->request('application/json', '')), 'A script');
		$this->assertFalse($this->target(Controller::class, 'index')->isPageNavigation($this->request('text/html', 'true')), 'An OCS request');
		$this->assertFalse($this->target(Controller::class, 'index', 'POST')->isPageNavigation($this->request('text/html', '')), 'A form sent');
	}

	/**
	 * @param class-string<Controller> $class
	 */
	private function target(string $class, string $method, string $httpMethod = 'GET'): RequestTarget {
		$controller = $this->getMockBuilder($class)->disableOriginalConstructor()->onlyMethods([])->getMock();
		return RequestTarget::app($controller, $method, $httpMethod, '/index.php/apps/files/');
	}

	private function request(string $accept, string $ocs): IRequest {
		$request = $this->createMock(IRequest::class);
		$request->method('getHeader')->willReturnCallback(static fn (string $name): string => match ($name) {
			'Accept' => $accept,
			'OCS-APIREQUEST' => $ocs,
			default => '',
		});
		return $request;
	}
}
