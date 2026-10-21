<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\KnownDevice;

/**
 * The browsers a user logged in from before, recognised by the known-device
 * cookie (concept section 11.5.1).
 */
interface IKnownDevices {
	/**
	 * Forget the known device whose cookie the current request carries, if
	 * it is one of the account's. Called when a credential of the account
	 * was found in use from two networks at once: the cookie may have been
	 * copied together with it, so it must no longer count as proof.
	 */
	public function forgetCurrentDevice(string $uid, int $detectionId): void;
}
