<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\KnownDevice;

/**
 * No device is known: used while the app does not set known-device cookies.
 */
final class NullKnownDevices implements IKnownDevices {
	#[\Override]
	public function forgetCurrentDevice(string $uid, int $detectionId): void {
	}
}
