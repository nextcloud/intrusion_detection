<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Check\Checks\BreachedPasswordDetector;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\User\Events\PasswordUpdatedEvent;
use Psr\Log\LoggerInterface;

/**
 * A new password has not been checked against the breach list yet: forget
 * the result for the old one, so the new one is checked at the next login.
 * This runs whatever the check's mode, so a result never outlives the
 * password it was about.
 *
 * @template-implements IEventListener<PasswordUpdatedEvent>
 */
class BreachResetListener implements IEventListener {
	public function __construct(
		private readonly BreachedPasswordDetector $detector,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof PasswordUpdatedEvent) {
			return;
		}
		try {
			$this->detector->reset($event->getUser());
		} catch (\Throwable $e) {
			// A failure here must never break a password change.
			$this->logger->error('Intrusion detection could not reset the breach check of an account', ['exception' => $e]);
		}
	}
}
