<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IUserSession;
use OCP\User\Events\PasswordUpdatedEvent;
use Psr\Log\LoggerInterface;

/**
 * A new password, set anywhere (the password page, personal settings, an
 * administrator, a reset link), lifts the requirement to choose one, and
 * the current session's marker with it. Other marked sessions drop theirs
 * at their next request.
 *
 * @template-implements IEventListener<PasswordUpdatedEvent>
 */
class PasswordUpdatedListener implements IEventListener {
	public function __construct(
		private readonly PasswordChangeService $passwords,
		private readonly SessionState $state,
		private readonly IUserSession $userSession,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof PasswordUpdatedEvent) {
			return;
		}
		try {
			$uid = $event->getUser()->getUID();
			$this->passwords->clear($uid, 'password changed');
			if ($this->userSession->getUser()?->getUID() === $uid) {
				$this->state->remove(SessionState::PASSWORD_CHANGE);
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not lift a required password change', ['exception' => $e]);
		}
	}
}
