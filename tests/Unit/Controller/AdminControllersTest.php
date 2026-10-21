<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Controller;

use OCA\IntrusionDetection\Controller\AdminApiController;
use OCA\IntrusionDetection\Controller\BlocklistApiController;
use OCA\IntrusionDetection\Controller\DecoyApiController;
use OCA\IntrusionDetection\Controller\IncidentApiController;
use OCA\IntrusionDetection\Controller\NotificationApiController;
use OCA\IntrusionDetection\Controller\PayloadApiController;
use OCA\IntrusionDetection\Controller\PrivacyApiController;
use OCA\IntrusionDetection\Controller\SimulationApiController;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\AuthorizedAdminSetting;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\SubAdminRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

/**
 * Every controller of the admin page: administrators only, CSRF-protected,
 * and every change behind a recent password confirmation.
 */
class AdminControllersTest extends TestCase {
	/**
	 * Routes that take a body but change nothing: they compute a result
	 * from the input and are rate limited instead.
	 */
	private const READS_WITH_BODY = [
		PayloadApiController::class . '::test',
		PayloadApiController::class . '::checkSignatures',
	];

	/** Routes that call out (downloads, emails) and are rate limited on top */
	private const RATE_LIMITED = [
		BlocklistApiController::class . '::syncNow',
		DecoyApiController::class . '::create',
		NotificationApiController::class . '::test',
		PayloadApiController::class . '::test',
		PayloadApiController::class . '::checkSignatures',
		SimulationApiController::class . '::simulate',
		IncidentApiController::class . '::report',
		IncidentApiController::class . '::download',
	];

	public static function controllers(): array {
		return [
			[AdminApiController::class],
			[BlocklistApiController::class],
			[DecoyApiController::class],
			[NotificationApiController::class],
			[PayloadApiController::class],
			[PrivacyApiController::class],
			[SimulationApiController::class],
			[IncidentApiController::class],
		];
	}

	/**
	 * @param class-string $class
	 */
	#[DataProvider('controllers')]
	public function testAdministratorsOnly(string $class): void {
		$reflection = new \ReflectionClass($class);
		$openApi = $reflection->getAttributes(OpenAPI::class);
		$this->assertCount(1, $openApi);
		$this->assertSame(OpenAPI::SCOPE_ADMINISTRATION, $openApi[0]->getArguments()['scope']);
		$relaxing = [NoAdminRequired::class, SubAdminRequired::class, PublicPage::class, AuthorizedAdminSetting::class, NoCSRFRequired::class];
		foreach ($reflection->getAttributes() as $attribute) {
			$this->assertNotContains($attribute->getName(), $relaxing, $class);
		}
		foreach (self::routes($class) as $method) {
			foreach ($relaxing as $forbidden) {
				$this->assertSame([], $method->getAttributes($forbidden), $method->getName() . ' must not carry ' . $forbidden);
			}
			$this->assertStringStartsWith('/api/v1/', $method->getAttributes(ApiRoute::class)[0]->getArguments()['url']);
		}
	}

	/**
	 * @param class-string $class
	 */
	#[DataProvider('controllers')]
	public function testEveryChangeNeedsPasswordConfirmation(string $class): void {
		foreach (self::routes($class) as $method) {
			$verb = $method->getAttributes(ApiRoute::class)[0]->getArguments()['verb'];
			$id = $class . '::' . $method->getName();
			$confirmation = $method->getAttributes(PasswordConfirmationRequired::class);
			if ($verb === 'GET' || in_array($id, self::READS_WITH_BODY, true)) {
				$this->assertSame([], $confirmation, $id . ' only reads');
			} else {
				$this->assertCount(1, $confirmation, $id . ' changes something and needs password confirmation');
			}
		}
	}

	public function testCallsOutAreRateLimited(): void {
		foreach (self::RATE_LIMITED as $id) {
			[$class, $name] = explode('::', $id);
			$this->assertCount(1, (new \ReflectionMethod($class, $name))->getAttributes(UserRateLimit::class), $id);
		}
	}

	public function testNoRouteIsDefinedTwice(): void {
		$routes = [];
		foreach (self::controllers() as [$class]) {
			foreach (self::routes($class) as $method) {
				$arguments = $method->getAttributes(ApiRoute::class)[0]->getArguments();
				$routes[] = $arguments['verb'] . ' ' . $arguments['url'];
			}
		}
		$this->assertSame(count($routes), count(array_unique($routes)));
	}

	/**
	 * No parameter may be called "format": core reads it as the response
	 * format, and the page would get XML instead of JSON.
	 */
	#[DataProvider('controllers')]
	public function testNoParameterChoosesTheResponseFormat(string $class): void {
		$names = [];
		foreach (self::routes($class) as $method) {
			foreach ($method->getParameters() as $parameter) {
				$names[] = $parameter->getName();
			}
		}
		$this->assertNotContains('format', $names);
	}

	/**
	 * @param class-string $class
	 * @return list<\ReflectionMethod>
	 */
	private static function routes(string $class): array {
		$routes = [];
		foreach ((new \ReflectionClass($class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
			if ($method->getAttributes(ApiRoute::class) !== []) {
				$routes[] = $method;
			}
		}
		return $routes;
	}
}
