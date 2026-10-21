<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\SessionState;

use OCA\IntrusionDetection\Check\CredentialUse\CredentialSwitch;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialUse;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialUseResolver;
use OCA\IntrusionDetection\Check\CredentialUse\PresentedCredential;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Listener\CredentialUseLoginListener;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\Rules\CredentialUseRule;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\ISession;
use OCP\IUser;
use OCP\User\Events\UserLoggedInEvent;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * The two places after authentication that hand a request to the
 * credential check: they cost nothing while the guard noted nothing.
 */
class CredentialUseRuleTest extends TestCase {
	private RequestContext $context;
	private CredentialUseResolver&MockObject $resolver;
	private ContainerInterface&MockObject $container;

	protected function setUp(): void {
		parent::setUp();
		$this->context = new RequestContext();
		$this->resolver = $this->createMock(CredentialUseResolver::class);
		$this->container = $this->createMock(ContainerInterface::class);
		$this->container->method('get')->with(CredentialUseResolver::class)->willReturn($this->resolver);
	}

	public function testNothingNotedLoadsNothing(): void {
		$this->container->expects($this->never())->method('get');
		$this->assertNull($this->rule()->check($this->state(), RequestTarget::dav('GET', '/remote.php/dav/')));
		$this->listener()->handle(new UserLoggedInEvent($this->createMock(IUser::class), 'alice', null, true));

		// A browser session with nothing pending is decided by the guard alone.
		$this->context->set(CredentialUseResolver::CONTEXT_KEY, new CredentialUse(PresentedCredential::SCHEME_SESSION, true));
		$this->assertNull($this->rule()->check($this->state(), RequestTarget::dav('GET', '/remote.php/dav/')));
	}

	public function testAPendingSwitchIsResolvedAndNeverBlocks(): void {
		$use = new CredentialUse(PresentedCredential::SCHEME_BASIC, false);
		$use->switch = new CredentialSwitch('198.51.100.7', '198.51.100.0/24', '203.0.113.9', '203.0.113.0/24', 4, 3, 1, 2);
		$this->context->set(CredentialUseResolver::CONTEXT_KEY, $use);
		$this->resolver->expects($this->once())->method('resolve')->with(true);
		$this->assertNull($this->rule()->check($this->state(), RequestTarget::dav('GET', '/remote.php/dav/')));
	}

	public function testAHeaderNextToASessionCookieIsResolved(): void {
		$this->context->set(CredentialUseResolver::CONTEXT_KEY, new CredentialUse(PresentedCredential::SCHEME_BASIC, true));
		$this->resolver->expects($this->once())->method('resolve');
		$this->rule()->check($this->state(), RequestTarget::dav('GET', '/remote.php/dav/'));
	}

	public function testTheLoginListenerPassesTheLoginOnAndNeverBreaksIt(): void {
		$this->context->set(CredentialUseResolver::CONTEXT_KEY, new CredentialUse(PresentedCredential::SCHEME_BASIC, false));
		$user = $this->createMock(IUser::class);
		$this->resolver->expects($this->once())->method('loggedIn')->with($user, 'alice', false)->willThrowException(new \RuntimeException('broken'));
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error');
		(new CredentialUseLoginListener($this->context, $this->container, $logger))->handle(new UserLoggedInEvent($user, 'alice', 'password', false));
	}

	private function rule(): CredentialUseRule {
		return new CredentialUseRule($this->context, $this->container);
	}

	private function listener(): CredentialUseLoginListener {
		return new CredentialUseLoginListener($this->context, $this->container, $this->createMock(LoggerInterface::class));
	}

	private function state(): SessionState {
		return new SessionState($this->createMock(ISession::class), $this->createMock(LoggerInterface::class));
	}
}
