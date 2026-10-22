<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Check\Checks\AccountTakeover\AccountTakeover;
use OCA\IntrusionDetection\Check\Checks\SecondFactorFailed\SecondFactorFailed;
use OCA\IntrusionDetection\Event\DetectionCreatedEvent;
use OCA\IntrusionDetection\Event\WasThisYouAnsweredEvent;
use OCA\IntrusionDetection\Guide\SecureAccountGuide;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\User\Events\PasswordUpdatedEvent;
use Psr\Log\LoggerInterface;

/**
 * Starts the "Secure my account" checklist (concept section 15.3) after
 * "No, it was not me", and when a check that means someone else had the
 * password acted (not when it only observed). Marks the password step done
 * when a new password is set. Fails open.
 *
 * @template-implements IEventListener<Event>
 */
class SecureGuideListener implements IEventListener {
	/** Checks whose enforced detections start the checklist */
	public const STARTING_CHECKS = [SecondFactorFailed::ID, AccountTakeover::ID];

	public function __construct(
		private readonly SecureAccountGuide $guide,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		try {
			if ($event instanceof WasThisYouAnsweredEvent && $event->isDenied()) {
				$detection = $event->getDetection();
				if ($detection->getUid() !== null) {
					$this->guide->start($detection->getUid(), SecureAccountGuide::REASON_DENIED, $detection->getId(), $detection->getCreatedAt());
				}
			} elseif ($event instanceof DetectionCreatedEvent) {
				$detection = $event->getDetection();
				if ($detection->getUid() !== null && $detection->isEnforced() && in_array($detection->getCheckId(), self::STARTING_CHECKS, true)) {
					$this->guide->start($detection->getUid(), SecureAccountGuide::REASON_DETECTION, $detection->getId(), $detection->getCreatedAt());
				}
			} elseif ($event instanceof PasswordUpdatedEvent) {
				$this->guide->passwordChanged($event->getUser()->getUID());
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not update the "Secure my account" checklist', ['exception' => $e]);
		}
	}
}
