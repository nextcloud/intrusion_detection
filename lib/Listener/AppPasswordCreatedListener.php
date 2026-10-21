<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Events\AppPasswordCreatedEvent;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use Psr\Log\LoggerInterface;

/**
 * Records where each new app password came from: the session (or app
 * password) the request was logged in with, and the address. Core keeps
 * neither, and ending a suspicious session must end what it created.
 *
 * Only ids are stored. Creating the app password never fails because of
 * this listener.
 *
 * @template-implements IEventListener<AppPasswordCreatedEvent>
 */
class AppPasswordCreatedListener implements IEventListener {
	public function __construct(
		private readonly Settings $settings,
		private readonly TokenOriginMapper $origins,
		private readonly CurrentSession $currentSession,
		private readonly IRequest $request,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof AppPasswordCreatedEvent) {
			return;
		}
		try {
			if (!$this->settings->isEnabled()) {
				return;
			}
			$token = $event->getToken();
			$creator = $this->currentSession->tokenId();
			$ip = $this->request->getRemoteAddress();
			$this->origins->record(
				$token->getId(),
				$token->getUID(),
				filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : null,
				$creator !== $token->getId() ? $creator : null,
				$this->timeFactory->getTime(),
			);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not record where an app password came from', ['exception' => $e]);
		}
	}
}
