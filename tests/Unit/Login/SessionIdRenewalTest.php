<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Login;

use OCA\IntrusionDetection\Login\SessionIdRenewal;
use OCP\Session\Exceptions\SessionNotAvailableException;
use OCP\Session\ISessionIdRenewer;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * The session id is renewed through core where the server can, and a
 * failure leaves the session as it was.
 */
class SessionIdRenewalTest extends TestCase {
	/** @var ContainerInterface&MockObject */
	private ContainerInterface $container;
	/** @var ISessionIdRenewer&MockObject */
	private ISessionIdRenewer $renewer;
	/** @var LoggerInterface&MockObject */
	private LoggerInterface $logger;

	protected function setUp(): void {
		parent::setUp();
		$this->renewer = $this->createMock(ISessionIdRenewer::class);
		$this->container = $this->createMock(ContainerInterface::class);
		$this->container->method('get')->with(ISessionIdRenewer::class)->willReturn($this->renewer);
		$this->logger = $this->createMock(LoggerInterface::class);
	}

	public function testRenewsThroughCore(): void {
		$this->renewer->expects($this->once())->method('renewSessionId');
		$this->assertTrue($this->renewal(true)->renew());
	}

	public function testWithoutCoresApiNothingChanges(): void {
		$this->container->expects($this->never())->method('get');
		$this->assertFalse($this->renewal(false)->renew());
	}

	public function testAFailureIsLoggedAndTheSessionGoesOn(): void {
		$this->renewer->method('renewSessionId')->willThrowException(new SessionNotAvailableException());
		$this->logger->expects($this->once())->method('warning');
		$this->assertFalse($this->renewal(true)->renew());
	}

	public function testTheServerHasTheApi(): void {
		$this->renewer->expects($this->once())->method('renewSessionId');
		$this->assertTrue((new SessionIdRenewal($this->container, $this->logger))->renew());
	}

	private function renewal(bool $available): SessionIdRenewal {
		return new FixedSessionIdRenewal($this->container, $this->logger, $available);
	}
}
