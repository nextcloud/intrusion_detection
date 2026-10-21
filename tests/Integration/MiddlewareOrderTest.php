<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\AppFramework\Bootstrap\Coordinator;
use OC\AppFramework\DependencyInjection\DIContainer;
use OC\AppFramework\Middleware\MiddlewareDispatcher;
use OC\Core\Middleware\TwoFactorMiddleware;
use OCA\IntrusionDetection\Middleware\SessionStateMiddleware;
use OCP\Server;
use Test\TestCase;

/**
 * The session-state middleware is global, and runs after core's two-factor
 * middleware: a login that still needs its second factor goes to the
 * challenge first.
 */
class MiddlewareOrderTest extends TestCase {
	public function testItRunsInEveryAppAfterTheTwoFactorMiddleware(): void {
		$context = Server::get(Coordinator::class)->getRegistrationContext();
		if ($context === null) {
			$this->markTestSkipped('The apps are not registered in this test run');
		}
		$registrations = array_filter(
			$context->getMiddlewareRegistrations(),
			static fn ($registration): bool => $registration->getService() === SessionStateMiddleware::class,
		);
		$this->assertCount(1, $registrations);
		$this->assertTrue(array_values($registrations)[0]->isGlobal());

		// Another app's middleware stack, as its requests see it.
		$container = new DIContainer('files');
		$classes = array_map(static fn (object $m): string => $m::class, $container->get(MiddlewareDispatcher::class)->getMiddlewares());
		$twoFactor = array_search(TwoFactorMiddleware::class, $classes, true);
		$sessionState = array_search(SessionStateMiddleware::class, $classes, true);
		$this->assertIsInt($twoFactor);
		$this->assertIsInt($sessionState);
		$this->assertGreaterThan($twoFactor, $sessionState);
	}
}
