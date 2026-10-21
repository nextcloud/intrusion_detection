<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Check\Checks\BreachedPassword;
use OCA\IntrusionDetection\Check\Checks\BreachedPasswordDetector;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Login\InteractiveLogin;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use OCP\User\Events\UserLoggedInEvent;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Checks the password of an interactive password login against the breach
 * list, when the check runs and the account is due (concept section 10.5).
 * Logins with app passwords and tokens, and clients that send the password
 * with Basic auth, are never checked.
 *
 * @template-implements IEventListener<UserLoggedInEvent>
 */
class BreachedPasswordListener implements IEventListener {
	public function __construct(
		private readonly Settings $settings,
		private readonly InteractiveLogin $interactive,
		private readonly IRequest $request,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof UserLoggedInEvent) {
			return;
		}
		try {
			// Off by default: stop before loading the detector and its HTTP client.
			if (!$this->settings->modeState(BreachedPassword::ID)->runs() || !$this->interactive->isPasswordLogin($event)) {
				return;
			}
			$this->container->get(BreachedPasswordDetector::class)->checkAtLogin(
				$event->getUser(),
				(string)$event->getPassword(),
				$this->request->getHeader('User-Agent'),
			);
		} catch (\Throwable $e) {
			// A failure here must never break a login.
			$this->logger->error('Intrusion detection could not check the password against the breach list', ['exception' => $e]);
		}
	}
}
