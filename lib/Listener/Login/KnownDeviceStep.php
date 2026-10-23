<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener\Login;

use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\LoginConfirmations;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;

/**
 * Recognises the browser a person logs in with, when the account
 * remembered it (concept section 12.2, step 3): the login proved the
 * device, and the history and the security notice know it.
 */
class KnownDeviceStep implements ILoginStep {
	public function __construct(
		private readonly KnownDevices $devices,
		private readonly LoginConfirmations $confirmations,
	) {
	}

	#[\Override]
	public static function appliesTo(LoginFacts $facts): bool {
		return $facts->kind->isInteractive() && !$facts->isBypassListed();
	}

	#[\Override]
	public function handle(LoginFacts $facts): void {
		$device = $this->devices->recognise($facts->uid());
		if ($device === null) {
			return;
		}
		$facts->device = $device;
		$this->devices->used($device);
		$this->confirmations->proved($facts->uid(), IConfirmationMethod::KNOWN_DEVICE);
	}
}
