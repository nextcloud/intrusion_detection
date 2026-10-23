<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\SessionState;

use OC\Session\Memory;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\SessionState\SessionGate;
use OCA\IntrusionDetection\SessionState\SessionStateRules;
use OCP\AppFramework\Controller;
use OCP\IRequest;
use OCP\IUserSession;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * The one decision of the middleware and the WebDAV plugin: visitors are
 * not looked at, and the gate never throws.
 */
class SessionGateTest extends TestCase {
	private SessionMarkers $markers;
	private bool $loggedIn = true;
	private bool $broken = false;

	protected function setUp(): void {
		parent::setUp();
		$this->markers = new SessionMarkers(new Memory(), $this->createMock(LoggerInterface::class));
	}

	public function testRequestsOfVisitorsAreNotLookedAt(): void {
		$this->loggedIn = false;
		$this->broken = true;
		$this->assertNull($this->gate()->decide($this->createMock(Controller::class), 'index'));
		$this->assertNull($this->gate()->decideDav('PROPFIND', '/remote.php/dav/files/alice/'));
	}

	public function testAnErrorWithoutAPendingStepUpLetsTheRequestPass(): void {
		$this->broken = true;
		$this->assertNull($this->gate()->decide($this->createMock(Controller::class), 'index'));
		$this->assertNull($this->gate()->decideDav('PROPFIND', '/remote.php/dav/files/alice/'));
	}

	private function gate(): SessionGate {
		$userSession = $this->createMock(IUserSession::class);
		$userSession->method('isLoggedIn')->willReturnCallback(fn (): bool => $this->loggedIn);
		$request = $this->createMock(IRequest::class);
		$request->method('getMethod')->willReturn('GET');
		$request->method('getRequestUri')->willReturnCallback(fn (): string => $this->broken ? throw new \RuntimeException('broken request') : '/index.php/apps/files/');
		$request->method('getParam')->willReturnCallback(fn (): mixed => $this->broken ? throw new \RuntimeException('broken request') : null);
		$request->method('getHeader')->willReturnCallback(fn (): string => $this->broken ? throw new \RuntimeException('broken request') : '');
		$rules = new SessionStateRules($this->createMock(ContainerInterface::class), $this->createMock(LoggerInterface::class), new RequestContext(), $request);
		return new SessionGate($rules, $this->markers, $userSession, $request, $this->createMock(LoggerInterface::class));
	}
}
