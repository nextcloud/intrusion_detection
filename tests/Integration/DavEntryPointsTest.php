<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\DAV\Events\SabrePluginAddEvent;
use OCA\IntrusionDetection\Dav\GuardDecisionPlugin;
use OCA\IntrusionDetection\Dav\SessionStatePlugin;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IRequest;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Sabre\DAV\Server as SabreServer;

/**
 * Every DAV endpoint of remote.php that serves a logged-in account carries
 * the session rules, through the app's own listener. The endpoints are read
 * from remote.php, so that a new one is covered or listed here.
 */
#[Group('DB')]
class DavEntryPointsTest extends IntegrationTestCase {
	/** Endpoints without an account session: direct download links carry their own token */
	private const WITHOUT_SESSION = ['dav/appinfo/v2/direct.php'];
	private const STOP = 'stop before the server starts';

	/**
	 * @return array<string, array{string}>
	 */
	public static function endpoints(): array {
		$source = (string)file_get_contents(\OC::$SERVERROOT . '/remote.php');
		preg_match_all("/'([a-z]+)' => '(dav\/appinfo\/[a-z0-9\/]+\.php)'/", $source, $matches, PREG_SET_ORDER);
		$endpoints = [];
		foreach ($matches as [, $service, $file]) {
			if (!in_array($file, self::WITHOUT_SESSION, true)) {
				$endpoints[$service] = [$file];
			}
		}
		return $endpoints;
	}

	public function testRemotePhpListsTheKnownEndpoints(): void {
		$files = array_unique(array_column(self::endpoints(), 0));
		sort($files);
		$this->assertSame(['dav/appinfo/v1/caldav.php', 'dav/appinfo/v1/carddav.php', 'dav/appinfo/v1/webdav.php', 'dav/appinfo/v2/remote.php'], $files);
	}

	#[DataProvider('endpoints')]
	public function testTheEndpointCarriesTheSessionRules(string $file): void {
		$server = $this->serverOf(\OC::$SERVERROOT . '/apps/' . $file);

		$this->assertInstanceOf(SabreServer::class, $server, 'The endpoint lets apps add plugins');
		$this->assertInstanceOf(SessionStatePlugin::class, $server->getPlugin('intrusion-detection-session-state'));
		$this->assertInstanceOf(GuardDecisionPlugin::class, $server->getPlugin('intrusion-detection-guard-decisions'), 'Guard hits decided at the login refuse WebDAV requests too');
	}

	/**
	 * Runs an endpoint up to SabrePluginAddEvent, after the app's listener,
	 * and returns the server.
	 */
	private function serverOf(string $endpoint): ?SabreServer {
		$request = $this->createMock(IRequest::class);
		$request->method('getRequestUri')->willReturn('/remote.php/dav/');
		$request->method('getMethod')->willReturn('PROPFIND');
		$this->overwriteService(IRequest::class, $request);
		$captured = null;
		$listener = static function (SabrePluginAddEvent $event) use (&$captured): void {
			$captured = $event->getServer();
			throw new \RuntimeException(self::STOP);
		};
		$dispatcher = Server::get(IEventDispatcher::class);
		$dispatcher->addListener(SabrePluginAddEvent::class, $listener, -1000);
		// The endpoints close every output buffer; PHPUnit expects its own back.
		$level = ob_get_level();
		try {
			(static function (string $endpoint): void {
				$baseuri = '/remote.php/dav/';
				require $endpoint;
			})($endpoint);
		} catch (\RuntimeException $e) {
			$this->assertSame(self::STOP, $e->getMessage());
		} finally {
			while (ob_get_level() < $level) {
				ob_start();
			}
			$dispatcher->removeListener(SabrePluginAddEvent::class, $listener);
			$this->restoreService(IRequest::class);
		}
		return $captured;
	}
}
