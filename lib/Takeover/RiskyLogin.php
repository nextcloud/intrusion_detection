<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Takeover;

/**
 * A login that was risky: when it happened, and why.
 */
final class RiskyLogin {
	/** The login needed a confirmation, and it was allowed without one */
	public const REASON_UNCONFIRMED = 'unconfirmed';
	/** The login came from an unknown device with a raised address risk score */
	public const REASON_UNKNOWN_DEVICE = 'unknown_device';
	/** The login came from a hosting provider or a Tor exit node */
	public const REASON_RISKY_NETWORK = 'risky_network';

	/**
	 * @param list<string> $policies the confirmation policies that applied, if any
	 */
	public function __construct(
		public readonly int $at,
		public readonly string $reason,
		public readonly array $policies = [],
	) {
	}
}
