<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Event;

use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\Detection;
use OCP\App\IAppManager;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventDispatcher;
use Psr\Log\LoggerInterface;

/**
 * Dispatches the app's typed events.
 *
 * Request guards run before any app has booted, and webhook_listeners only
 * subscribes to the events that have webhooks when it boots. So before an
 * event is dispatched, webhook_listeners is booted if it is enabled;
 * otherwise a trap URL or payload probe would never reach a webhook.
 */
class TypedEvents {
	public const WEBHOOK_APP = 'webhook_listeners';

	private bool $webhooksBooted = false;

	public function __construct(
		private readonly IEventDispatcher $dispatcher,
		private readonly IAppManager $appManager,
		private readonly EventPayloads $payloads,
		private readonly LoggerInterface $logger,
	) {
	}

	public function detectionCreated(Detection $detection): void {
		$this->dispatch(new DetectionCreatedEvent($detection, $this->payloads));
	}

	public function banCreated(Ban $ban, bool $raised): void {
		$this->dispatch(new BanCreatedEvent($ban, $raised, $this->payloads));
	}

	public function banLifted(Ban $ban): void {
		$this->dispatch(new BanLiftedEvent($ban, $this->payloads));
	}

	private function dispatch(Event $event): void {
		$this->bootWebhooks();
		$this->dispatcher->dispatchTyped($event);
	}

	private function bootWebhooks(): void {
		if ($this->webhooksBooted) {
			return;
		}
		$this->webhooksBooted = true;
		try {
			if (!$this->appManager->isAppLoaded(self::WEBHOOK_APP) && $this->appManager->isEnabledForAnyone(self::WEBHOOK_APP)) {
				$this->appManager->loadApp(self::WEBHOOK_APP);
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not load webhook_listeners before dispatching an event', ['exception' => $e]);
		}
	}
}
