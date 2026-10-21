<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Guard\DeferredHits;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\User\Events\UserLoggedInEvent;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Decides the guard hits of a request that logs in with Basic auth, an app
 * password or a Bearer token (an injection probe, a trap URL,
 * {@see DeferredHits}): the login names the user.
 *
 * @template-implements IEventListener<UserLoggedInEvent>
 */
class PayloadLoginListener implements IEventListener {
	public function __construct(
		private readonly RequestContext $context,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		// Nearly every login has nothing pending: stop before loading anything.
		if (!$event instanceof UserLoggedInEvent || !DeferredHits::isPending($this->context)) {
			return;
		}
		try {
			$this->container->get(DeferredHits::class)->resolve($event->getUser());
		} catch (\Throwable $e) {
			// A failure here must never break a login.
			$this->logger->error('Intrusion detection could not record a request guard hit', ['exception' => $e]);
		}
	}
}
