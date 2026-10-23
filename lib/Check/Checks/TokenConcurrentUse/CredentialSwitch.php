<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;

/**
 * A credential that switched back and forth between two networks often
 * enough to count as used from both at the same time. Only addresses and
 * counts, never anything about the credential itself.
 */
final class CredentialSwitch {
	public function __construct(
		/** The address of the last use from the other network */
		public readonly string $otherIp,
		public readonly string $otherNet,
		/** The address of the request that made the last switch */
		public readonly string $currentIp,
		public readonly string $currentNet,
		/** 4 or 6 */
		public readonly int $family,
		/** Switches between the two networks within the window */
		public readonly int $switches,
		/** When the first of those switches happened */
		public readonly int $firstSwitchAt,
		public readonly int $at,
	) {
	}
}
