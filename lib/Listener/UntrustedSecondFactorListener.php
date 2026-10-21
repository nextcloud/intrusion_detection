<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\UntrustedSecondFactors;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderForUserRegistered;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderForUserUnregistered;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use Psr\Log\LoggerInterface;

/**
 * Marks a second factor set up from an unconfirmed session, and drops the
 * mark when it is removed ({@see UntrustedSecondFactors}). Core recording
 * the state of a provider it had none for is no change. Fails open.
 *
 * @template-implements IEventListener<TwoFactorProviderForUserRegistered|TwoFactorProviderForUserUnregistered>
 */
class UntrustedSecondFactorListener implements IEventListener {
	public function __construct(
		private readonly Settings $settings,
		private readonly UntrustedSecondFactors $untrusted,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof TwoFactorProviderForUserRegistered && !$event instanceof TwoFactorProviderForUserUnregistered) {
			return;
		}
		try {
			if (!$this->settings->isEnabled() || SecurityChangeListener::isStateBackfill()) {
				return;
			}
			$uid = $event->getUser()->getUID();
			$providerId = $event->getProvider()->getId();
			if ($event instanceof TwoFactorProviderForUserRegistered) {
				$this->untrusted->registered($uid, $providerId);
			} else {
				$this->untrusted->unregistered($uid, $providerId);
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not note a new second factor', ['exception' => $e]);
		}
	}
}
