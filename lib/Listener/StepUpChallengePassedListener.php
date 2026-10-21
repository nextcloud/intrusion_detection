<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengePassed;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use Psr\Log\LoggerInterface;

/**
 * A second factor was solved in a session whose login waits for its extra
 * confirmation, after the user chose "Confirm with your second factor" on
 * the verify page: the login is confirmed.
 *
 * Only a second factor that the account had when the login happened
 * counts (it is in the step-up's methods). A provider set up during the
 * pending login, with just the password, confirms nothing.
 *
 * @template-implements IEventListener<TwoFactorProviderChallengePassed>
 */
class StepUpChallengePassedListener implements IEventListener {
	public function __construct(
		private readonly StepUpService $stepUps,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof TwoFactorProviderChallengePassed) {
			return;
		}
		try {
			$stepUp = $this->stepUps->current();
			if ($stepUp === null
				|| !$stepUp->isPending()
				|| !$stepUp->secondFactorRequested
				|| !$stepUp->hasMethod(IConfirmationMethod::SECOND_FACTOR)
				|| $stepUp->uid !== $event->getUser()->getUID()) {
				return;
			}
			$this->stepUps->complete($stepUp, IConfirmationMethod::SECOND_FACTOR);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not confirm a login with the second factor', ['exception' => $e]);
		}
	}
}
