<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Event\WasThisYouAnsweredEvent;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IUserSession;
use OCP\User\Events\PasswordUpdatedEvent;
use Psr\Log\LoggerInterface;

/**
 * Forgets remembered devices when they may no longer prove anything
 * (concept section 11.5.1):
 *
 * - "No, it was not me": all of the account's devices. Which device the
 *   unwanted login used cannot be told for sure, and a copied cookie must
 *   not keep working.
 * - A new password: all of them, except the browser the account holder
 *   changed it from. When someone else set it (an administrator, occ, a
 *   reset link), all of them.
 *
 * @template-implements IEventListener<WasThisYouAnsweredEvent|PasswordUpdatedEvent>
 */
class KnownDeviceListener implements IEventListener {
	public function __construct(
		private readonly KnownDevices $devices,
		private readonly IUserSession $userSession,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		try {
			if ($event instanceof WasThisYouAnsweredEvent && $event->isDenied()) {
				$uid = $event->getDetection()->getUid();
				if ($uid !== null) {
					$this->devices->forgetAll($uid, 'the user answered "No, it was not me"');
				}
			} elseif ($event instanceof PasswordUpdatedEvent) {
				$uid = $event->getUser()->getUID();
				$own = $this->userSession->getUser()?->getUID() === $uid;
				$this->devices->forgetAll($uid, 'the password changed', $own);
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not forget known devices', ['exception' => $e]);
		}
	}
}
