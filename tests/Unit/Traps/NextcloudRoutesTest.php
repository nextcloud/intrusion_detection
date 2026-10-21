<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Traps;

use OCA\IntrusionDetection\Traps\TrapPaths;
use OCP\Route\IRouter;
use OCP\Server;
use Test\TestCase;

/**
 * The trap paths must never match anything Nextcloud serves itself. Boots
 * the router with the routes of every enabled app, so a new route that
 * collides fails here.
 */
class NextcloudRoutesTest extends TestCase {
	/**
	 * Entry points, well-known URLs and static paths that are not routes.
	 */
	private const SERVED = [
		'/index.php', '/remote.php/dav/', '/remote.php/webdav/', '/public.php/dav/', '/status.php', '/cron.php',
		'/ocs/v1.php/cloud/capabilities', '/ocs/v2.php/apps/files/api/v1', '/ocs-provider/', '/ocm-provider/',
		'/.well-known/caldav', '/.well-known/carddav', '/.well-known/webfinger', '/.well-known/nodeinfo',
		'/.well-known/host-meta', '/.well-known/host-meta.json', '/.well-known/openid-configuration',
		'/.well-known/security.txt', '/.well-known/change-password', '/robots.txt', '/favicon.ico',
		'/core/img/favicon.ico', '/dist/core-main.js', '/updater/', '/s/AbCdEfGh', '/f/123', '/login', '/apps/files/',
	];

	/**
	 * @return list<string>
	 */
	private function routePaths(): array {
		$router = Server::get(IRouter::class);
		$router->loadRoutes();
		$paths = [];
		foreach ($router->getRouteCollection()->all() as $route) {
			// Placeholders become a plain value, as a real request would carry.
			$paths[] = (string)preg_replace('/\{[^}]+\}/', 'x', $route->getPath());
		}
		$this->assertGreaterThan(100, count($paths), 'The routes of the enabled apps are loaded');
		return $paths;
	}

	public function testNoTrapMatchesARoute(): void {
		foreach ($this->routePaths() as $path) {
			$normalised = TrapPaths::normalise($path, '');
			$this->assertNull(TrapPaths::match($normalised, true, true, []), 'Trap matches the route ' . $path);
			$this->assertNull(TrapPaths::match('/index.php' . $normalised, true, true, []), 'Trap matches the route ' . $path);
		}
	}

	public function testNoTrapMatchesAnEntryPointOrWellKnownUrl(): void {
		foreach (self::SERVED as $path) {
			$this->assertNull(TrapPaths::match(TrapPaths::normalise($path, ''), true, true, []), 'Trap matches ' . $path);
		}
	}

	public function testEveryRouteSegmentIsProtectedFromCustomPaths(): void {
		foreach ($this->routePaths() as $path) {
			$segment = explode('/', ltrim($path, '/'))[0];
			$this->assertContains($segment, TrapPaths::NEXTCLOUD_SEGMENTS, 'The first segment of ' . $path . ' must be in NEXTCLOUD_SEGMENTS');
		}
		foreach (self::SERVED as $path) {
			$this->assertTrue(TrapPaths::conflictsWithNextcloud($path), $path . ' must not be usable as a custom trap');
		}
	}
}
