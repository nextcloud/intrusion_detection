<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Event;

use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Event\BanCreatedEvent;
use OCA\IntrusionDetection\Event\BanLiftedEvent;
use OCA\IntrusionDetection\Event\DetectionCreatedEvent;
use OCA\IntrusionDetection\Event\EventPayloads;
use OCA\IntrusionDetection\Event\TypedEvents;
use OCP\App\IAppManager;
use OCP\EventDispatcher\IEventDispatcher;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class TypedEventsTest extends TestCase {
	private IEventDispatcher&MockObject $dispatcher;
	private IAppManager&MockObject $appManager;
	private LoggerInterface&MockObject $logger;
	/** @var list<object> */
	private array $dispatched = [];

	protected function setUp(): void {
		parent::setUp();
		$this->dispatcher = $this->createMock(IEventDispatcher::class);
		$this->dispatcher->method('dispatchTyped')->willReturnCallback(function (object $event): void {
			$this->dispatched[] = $event;
		});
		$this->appManager = $this->createMock(IAppManager::class);
		$this->logger = $this->createMock(LoggerInterface::class);
	}

	public function testWebhookListenersIsBootedOnceBeforeTheFirstEvent(): void {
		$this->appManager->method('isAppLoaded')->with('webhook_listeners')->willReturn(false);
		$this->appManager->method('isEnabledForAnyone')->with('webhook_listeners')->willReturn(true);
		$this->appManager->expects($this->once())->method('loadApp')->with('webhook_listeners')
			->willReturnCallback(function (): void {
				$this->assertSame([], $this->dispatched, 'booted before the event is dispatched');
			});
		$events = $this->events();
		$events->detectionCreated(new Detection());
		$events->banCreated(new Ban(), true);
		$events->banLifted(new Ban());
		$this->assertInstanceOf(DetectionCreatedEvent::class, $this->dispatched[0]);
		$this->assertInstanceOf(BanCreatedEvent::class, $this->dispatched[1]);
		$this->assertTrue($this->dispatched[1]->isRaised());
		$this->assertInstanceOf(BanLiftedEvent::class, $this->dispatched[2]);
	}

	public function testNothingIsLoadedWhenWebhooksAreLoadedOrDisabled(): void {
		$this->appManager->method('isAppLoaded')->willReturnOnConsecutiveCalls(true, false);
		$this->appManager->method('isEnabledForAnyone')->willReturn(false);
		$this->appManager->expects($this->never())->method('loadApp');
		$this->events()->detectionCreated(new Detection());
		$this->events()->detectionCreated(new Detection());
		$this->assertCount(2, $this->dispatched);
	}

	public function testAFailingBootIsLoggedAndTheEventStillDispatched(): void {
		$this->appManager->method('isAppLoaded')->willReturn(false);
		$this->appManager->method('isEnabledForAnyone')->willReturn(true);
		$this->appManager->method('loadApp')->willThrowException(new \RuntimeException('broken'));
		$this->logger->expects($this->once())->method('error');
		$this->events()->banLifted(new Ban());
		$this->assertCount(1, $this->dispatched);
	}

	private function events(): TypedEvents {
		return new TypedEvents($this->dispatcher, $this->appManager, $this->createMock(EventPayloads::class), $this->logger);
	}
}
