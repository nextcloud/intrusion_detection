<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener\Login;

use OCA\IntrusionDetection\Check\Checks\NewLogin\UnfamiliarLogin;
use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Confirm\LoginDetections;
use OCA\IntrusionDetection\Signal\SignalDispatcher;

/**
 * Judges a person's login that nothing asked them about
 * ({@see \OCA\IntrusionDetection\Check\Checks\NewLogin\NewLoginDetector}):
 * one from no remembered device that the step-up neither asked for,
 * proved, nor let in without its confirmation. After the known-device
 * step, which finds the device, and before the history step, so that the
 * login is not its own habit. What it records waits for the login's
 * session, so that "No, it was not me" ends that session.
 */
class NewLoginStep implements ILoginStep {
	public function __construct(
		private readonly SignalDispatcher $dispatcher,
		private readonly LoginDetections $loginDetections,
	) {
	}

	#[\Override]
	public static function appliesTo(LoginFacts $facts): bool {
		return $facts->kind->isInteractive() && $facts->source !== null && !$facts->isBypassListed();
	}

	#[\Override]
	public function handle(LoginFacts $facts): void {
		$status = $facts->confirmation?->status ?? ConfirmationStatus::None;
		if ($facts->device !== null || $facts->source === null || $status !== ConfirmationStatus::None || !$this->dispatcher->runs(UnfamiliarLogin::class)) {
			return;
		}
		$dispatch = $this->dispatcher->dispatch(new UnfamiliarLogin($facts->user, $facts->source, $facts->userAgent, $facts->kind->typesPassword()));
		$this->loginDetections->await($facts->uid(), array_map(static fn ($detection): string => (string)$detection->getId(), $dispatch->detections));
	}
}
