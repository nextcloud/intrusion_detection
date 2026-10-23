<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\DAV\Events\SabrePluginAddEvent;
use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Confirm\LoginConfirmation;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Dav\GuardDecisionPlugin;
use OCA\IntrusionDetection\Dav\RemoteSessionCheck;
use OCA\IntrusionDetection\Dav\SessionStatePlugin;
use OCA\IntrusionDetection\Login\RequestContext;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IRequest;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Sabre\DAV\Exception\NotAuthenticated;
use Sabre\DAV\Server as SabreServer;

/**
 * Every DAV endpoint of remote.php that serves a logged-in account carries
 * the session rules: through the app's own listener where the endpoint
 * lets apps add plugins, otherwise through {@see RemoteSessionCheck}, which
 * refuses unconfirmed logins on such a request itself. The endpoints are
 * read from remote.php, so that a new one is covered or listed here.
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
		$context = Server::get(RequestContext::class);
		$context->set(RemoteSessionCheck::PLUGINS_ADDED, false);
		$server = $this->serverOf(\OC::$SERVERROOT . '/apps/' . $file);

		if ($server === null) {
			// A server whose endpoint lets no app add plugins: the login itself is refused there.
			$this->assertFalse($context->get(RemoteSessionCheck::PLUGINS_ADDED));
			$this->expectException(NotAuthenticated::class);
			RemoteSessionCheck::atLogin($this->remoteRequest(), $context, LoginConfirmation::ofStepUp(new StepUpState('alice', ConfirmationStatus::RefusedClient, ['flagged_source'], time(), 0, null)));
			return;
		}
		$this->assertInstanceOf(SessionStatePlugin::class, $server->getPlugin('intrusion-detection-session-state'));
		$this->assertInstanceOf(GuardDecisionPlugin::class, $server->getPlugin('intrusion-detection-guard-decisions'), 'Guard hits decided at the login refuse WebDAV requests too');
		$this->assertTrue($context->get(RemoteSessionCheck::PLUGINS_ADDED), 'The plugins answer unconfirmed logins');
	}

	private function remoteRequest(): IRequest {
		$request = $this->createMock(IRequest::class);
		$request->method('getScriptName')->willReturn('/remote.php');
		return $request;
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
