<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Whether a login comes from where the account holder logs in: a device
 * they remembered, or the address of one of their recent logins that went
 * through (needed nothing, or was confirmed). Someone guessing the password
 * from elsewhere must not be able to lock them out from there.
 */
class FamiliarLogin {
	/** Logins this recent count */
	public const WINDOW = 30 * 86400;

	public function __construct(
		private readonly KnownDevices $devices,
		private readonly LoginHistoryMapper $history,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	public function isFamiliar(LoginContext $login): bool {
		if ($login->interactive && $this->devices->recognise($login->uid()) !== null) {
			return true;
		}
		return $login->source !== null
			&& $this->history->wentThroughFrom($login->uid(), $login->source->ip, $this->timeFactory->getTime() - self::WINDOW);
	}
}
