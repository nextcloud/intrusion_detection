<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check\Checks\InjectionProbe;

use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PayloadHit;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PayloadResponder;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PendingHit;
use OCA\IntrusionDetection\Guard\DeferredHits;
use OCA\IntrusionDetection\Listener\PayloadLoginListener;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IUser;
use OCP\User\Events\UserLoggedInEvent;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class PayloadLoginListenerTest extends TestCase {
	public function testNothingPendingLoadsNothing(): void {
		$container = $this->createMock(ContainerInterface::class);
		$container->expects($this->never())->method('get');
		$listener = new PayloadLoginListener(new RequestContext(), $container, $this->createMock(LoggerInterface::class));
		$listener->handle(new UserLoggedInEvent($this->createMock(IUser::class), 'alice', null, false));
	}

	public function testAFailureNeverBreaksTheLogin(): void {
		$context = new RequestContext();
		$context->set(PayloadResponder::CONTEXT_KEY, new PendingHit(
			new PayloadHit(PayloadHit::LOCATION_QUERY, 'id', ['sql_union_select' => 3], 3, 3, 'none', 'x'),
			SourceKey::fromIp('198.51.100.1'),
			PendingHit::CREDENTIAL_BASIC,
			null,
		));
		$responder = $this->createMock(PayloadResponder::class);
		$responder->method('resolve')->willThrowException(new \RuntimeException('database gone'));
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $class): object => $class === DeferredHits::class ? new DeferredHits($context, $container) : $responder);
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error');

		(new PayloadLoginListener($context, $container, $logger))->handle(new UserLoggedInEvent($this->createMock(IUser::class), 'alice', null, false));
	}
}
