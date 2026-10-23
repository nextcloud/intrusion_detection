<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\Methods\SecondFactorMethod;
use OCA\IntrusionDetection\Confirm\SessionConfirmation;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengePassed;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use Psr\Log\LoggerInterface;

/**
 * A second factor was solved in the current session:
 *
 * - a login that waits for its extra confirmation with the second factor
 *   (core's challenge at login, or "Confirm with your second factor" on
 *   the verify page) is confirmed;
 * - a login that needed no confirmation has proved the second factor
 *   ({@see SessionConfirmation});
 * - the login history notes the second factor of the session's login.
 *
 * Only a second factor that the account had when the login happened
 * counts (it is in the step-up's methods), and never a provider set up
 * from an unconfirmed session: the login then keeps waiting.
 *
 * @template-implements IEventListener<TwoFactorProviderChallengePassed>
 */
class ChallengePassedListener implements IEventListener {
	public function __construct(
		private readonly StepUpService $stepUps,
		private readonly SecondFactorMethod $method,
		private readonly SessionConfirmation $confirmation,
		private readonly LoginHistory $history,
		private readonly AppSettings $settings,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof TwoFactorProviderChallengePassed) {
			return;
		}
		try {
			$this->confirm($event);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not confirm a login with the second factor', ['exception' => $e]);
		}
		try {
			if ($this->settings->isEnabled()) {
				$this->history->secondFactorPassed($event->getUser()->getUID());
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not record a login', ['exception' => $e]);
		}
	}

	private function confirm(TwoFactorProviderChallengePassed $event): void {
		$user = $event->getUser();
		if (!$this->method->confirms($user, $event->getProvider()->getId())) {
			return;
		}
		$stepUp = $this->stepUps->current();
		if ($stepUp === null) {
			$this->confirmation->proved($user->getUID(), IConfirmationMethod::SECOND_FACTOR);
			return;
		}
		if (!$stepUp->isPending()
			|| !$stepUp->secondFactorRequested
			|| !$stepUp->hasMethod(IConfirmationMethod::SECOND_FACTOR)
			|| $stepUp->uid !== $user->getUID()) {
			return;
		}
		$this->stepUps->complete($stepUp, IConfirmationMethod::SECOND_FACTOR);
	}
}
