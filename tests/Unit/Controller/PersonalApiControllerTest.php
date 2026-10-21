<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Controller;

use OCA\IntrusionDetection\Controller\PersonalApiController;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\AuthorizedAdminSetting;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use Test\TestCase;

/**
 * Every endpoint of the user's own security section: for logged-in users,
 * CSRF-protected, every change rate limited, and a recent password
 * confirmation where the change vouches for something or ends sessions.
 */
class PersonalApiControllerTest extends TestCase {
	/** Changes that need the password: they trust a network, or end sessions */
	private const NEEDS_PASSWORD = ['confirm', 'logOutElsewhere'];

	public function testEveryRouteIsForLoggedInUsersAndCsrfProtected(): void {
		$class = new \ReflectionClass(PersonalApiController::class);
		$this->assertSame(OpenAPI::SCOPE_DEFAULT, $class->getAttributes(OpenAPI::class)[0]->getArguments()['scope']);
		$routes = self::routes();
		$this->assertContains('overview', array_keys($routes));
		$this->assertContains('logOutElsewhere', array_keys($routes));
		foreach ($routes as $name => $method) {
			$this->assertCount(1, $method->getAttributes(NoAdminRequired::class), $name . ' is for every user');
			foreach ([NoCSRFRequired::class, PublicPage::class, AuthorizedAdminSetting::class] as $forbidden) {
				$this->assertSame([], $method->getAttributes($forbidden), $name . ' must not carry ' . $forbidden);
			}
			$this->assertStringStartsWith('/api/v1/personal/', $method->getAttributes(ApiRoute::class)[0]->getArguments()['url']);
		}
	}

	public function testEveryChangeIsRateLimitedAndTheRightOnesNeedThePassword(): void {
		foreach (self::routes() as $name => $method) {
			$verb = $method->getAttributes(ApiRoute::class)[0]->getArguments()['verb'];
			$confirmation = $method->getAttributes(PasswordConfirmationRequired::class);
			if ($verb === 'GET') {
				$this->assertSame([], $method->getAttributes(UserRateLimit::class), $name . ' only reads');
				$this->assertSame([], $confirmation, $name . ' only reads');
				continue;
			}
			$this->assertCount(1, $method->getAttributes(UserRateLimit::class), $name . ' changes something');
			$this->assertCount(in_array($name, self::NEEDS_PASSWORD, true) ? 1 : 0, $confirmation, $name);
		}
	}

	public function testListsAreBounded(): void {
		foreach (self::routes() as $name => $method) {
			foreach ($method->getParameters() as $parameter) {
				if ($parameter->getName() === 'limit') {
					$this->assertMatchesRegularExpression('/@param int<1, \d+> \$limit/', (string)$method->getDocComment(), $name);
				}
			}
		}
	}

	/**
	 * @return array<string, \ReflectionMethod>
	 */
	private static function routes(): array {
		$routes = [];
		foreach ((new \ReflectionClass(PersonalApiController::class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
			if ($method->getAttributes(ApiRoute::class) !== []) {
				$routes[$method->getName()] = $method;
			}
		}
		return $routes;
	}
}
