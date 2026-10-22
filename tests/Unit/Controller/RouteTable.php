<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Controller;

use OCP\AppFramework\Http\Attribute\AnonRateLimit;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\BruteForceProtection;
use OCP\AppFramework\Http\Attribute\FrontpageRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\NoTwoFactorRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\Attribute\UseSession;

/**
 * Every route of the app's controllers, found by reflection, with the
 * attributes that decide who may call it and how.
 */
final class RouteTable {
	private const LIB = __DIR__ . '/../../../lib/Controller';

	/**
	 * The controllers of the app.
	 *
	 * @return list<class-string>
	 */
	public static function controllers(): array {
		$classes = [];
		foreach (glob(self::LIB . '/*.php') ?: [] as $file) {
			$class = 'OCA\\IntrusionDetection\\Controller\\' . basename($file, '.php');
			if (class_exists($class) && !(new \ReflectionClass($class))->isAbstract()) {
				$classes[] = $class;
			}
		}
		sort($classes);
		return $classes;
	}

	/**
	 * The route methods of a controller.
	 *
	 * @param class-string $class
	 * @return list<\ReflectionMethod>
	 */
	public static function methods(string $class): array {
		$routes = [];
		foreach ((new \ReflectionClass($class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
			if ($method->getAttributes(ApiRoute::class) !== [] || $method->getAttributes(FrontpageRoute::class) !== []) {
				$routes[] = $method;
			}
		}
		return $routes;
	}

	/**
	 * "VERB url" of a route method.
	 */
	public static function key(\ReflectionMethod $method): string {
		$route = ($method->getAttributes(ApiRoute::class)[0] ?? $method->getAttributes(FrontpageRoute::class)[0])->getArguments();
		return $route['verb'] . ' ' . $route['url'];
	}

	/**
	 * Every route as "VERB url" => its attributes: the OpenAPI scope, who
	 * may call it (admin, user or public), then password confirmation, CSRF,
	 * session, two-factor and the limits.
	 *
	 * @return array<string, string>
	 */
	public static function routes(): array {
		$table = [];
		foreach (self::controllers() as $class) {
			foreach (self::methods($class) as $method) {
				$table[self::key($method)] = self::describe($method);
			}
		}
		ksort($table);
		return $table;
	}

	private static function describe(\ReflectionMethod $method): string {
		$openApi = $method->getAttributes(OpenAPI::class)[0] ?? $method->getDeclaringClass()->getAttributes(OpenAPI::class)[0] ?? null;
		$parts = [$openApi === null ? 'no-openapi' : (string)($openApi->getArguments()['scope'] ?? $openApi->getArguments()[0] ?? OpenAPI::SCOPE_DEFAULT)];
		$parts[] = match (true) {
			self::has($method, PublicPage::class) => 'public',
			self::has($method, NoAdminRequired::class) => 'user',
			default => 'admin',
		};
		$flags = [
			PasswordConfirmationRequired::class => 'password',
			NoCSRFRequired::class => 'no-csrf',
			UseSession::class => 'session',
			NoTwoFactorRequired::class => 'no-2fa',
		];
		foreach ($flags as $attribute => $flag) {
			if (self::has($method, $attribute)) {
				$parts[] = $flag;
			}
		}
		foreach ([UserRateLimit::class => 'user-limit', AnonRateLimit::class => 'anon-limit'] as $attribute => $name) {
			foreach ($method->getAttributes($attribute) as $limit) {
				$arguments = $limit->getArguments();
				$parts[] = $name . ':' . $arguments['limit'] . '/' . $arguments['period'];
			}
		}
		foreach ($method->getAttributes(BruteForceProtection::class) as $bruteForce) {
			$parts[] = 'brute-force:' . $bruteForce->getArguments()['action'];
		}
		return implode(' ', $parts);
	}

	/**
	 * @param class-string $attribute
	 */
	private static function has(\ReflectionMethod $method, string $attribute): bool {
		return $method->getAttributes($attribute) !== [] || $method->getDeclaringClass()->getAttributes($attribute) !== [];
	}
}
