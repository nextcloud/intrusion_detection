<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialUse;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialUseResolver;
use OCA\IntrusionDetection\Login\RequestContext;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\User\Events\UserLoggedInEvent;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Tells the credential check that the request logged in. Core dispatches
 * the event for every login with Basic credentials, a Bearer token or a
 * session token that the request did not have a logged-in session for.
 *
 * @template-implements IEventListener<UserLoggedInEvent>
 */
class CredentialUseLoginListener implements IEventListener {
	public function __construct(
		private readonly RequestContext $context,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		// Nearly every login has nothing pending: stop before loading anything.
		if (!$event instanceof UserLoggedInEvent || !$this->context->get(CredentialUseResolver::CONTEXT_KEY) instanceof CredentialUse) {
			return;
		}
		try {
			$this->container->get(CredentialUseResolver::class)->loggedIn($event->getUser(), $event->getLoginName(), $event->isTokenLogin());
		} catch (\Throwable $e) {
			// A failure here must never break a login.
			$this->logger->error('Intrusion detection could not record a credential used from two networks', ['exception' => $e]);
		}
	}
}
