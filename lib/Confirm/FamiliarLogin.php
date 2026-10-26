<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Login\LoginContext;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\LoginHistory\SignInHabits;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Whether a login comes from where the account holder logs in: a device
 * they remembered, a network they trust, or the network of one of their
 * recent logins that went through (needed nothing, or was confirmed; with
 * the password, an app password or a token). Someone guessing the
 * password from elsewhere must not be able to lock them out from there,
 * and cannot make a place familiar without such a login.
 */
class FamiliarLogin {
	/** Logins this recent count, as for the habits on the personal page */
	public const WINDOW = SignInHabits::WINDOW;

	public function __construct(
		private readonly KnownDevices $devices,
		private readonly LoginHistory $history,
		private readonly TrustedNetworks $trustedNetworks,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	public function isFamiliar(LoginContext $login): bool {
		if ($this->devices->recognise($login->uid()) !== null) {
			return true;
		}
		$source = $login->source;
		if ($source === null) {
			return false;
		}
		return $this->trustedNetworks->isTrusted($login->uid(), $source)
			|| $this->history->wentThroughFrom($login->uid(), $source->netKey, $this->timeFactory->getTime() - self::WINDOW);
	}
}
