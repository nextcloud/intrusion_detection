<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Sensitive\SensitiveConfirmations;
use OCA\IntrusionDetection\Sensitive\SensitiveSession;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengePassed;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use Psr\Log\LoggerInterface;

/**
 * A second factor was solved:
 *
 * - it is a strong confirmation of the session's holder, which keeps an
 *   administrator's session from counting as risky for
 *   `sensitive_admin_max_age` ({@see SensitiveSession});
 * - when the user chose "Confirm with your second factor" on the confirm
 *   page, the sensitive action is confirmed.
 *
 * Only a second factor that the account had when the confirmation started
 * counts (it is among the offered methods).
 *
 * @template-implements IEventListener<TwoFactorProviderChallengePassed>
 */
class SensitiveChallengePassedListener implements IEventListener {
	public function __construct(
		private readonly SessionState $state,
		private readonly SensitiveSession $sensitive,
		private readonly SensitiveConfirmations $confirmations,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof TwoFactorProviderChallengePassed) {
			return;
		}
		try {
			$user = $event->getUser();
			$this->sensitive->strongConfirmation($this->state, $user->getUID());
			$pending = $this->confirmations->current($user);
			if ($pending !== null && $pending->isPending() && $pending->secondFactorRequested && $pending->hasMethod(IConfirmationMethod::SECOND_FACTOR)) {
				$this->confirmations->complete($pending, IConfirmationMethod::SECOND_FACTOR);
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not record a solved second factor', ['exception' => $e]);
		}
	}
}
