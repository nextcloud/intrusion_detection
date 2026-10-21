<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\CredentialUse;

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

	/**
	 * @return array{ip1: string, net1: string, ip2: string, net2: string, family: int, switches: int, first: int, last: int}
	 */
	public function facts(): array {
		return [
			'ip1' => $this->otherIp,
			'net1' => $this->otherNet,
			'ip2' => $this->currentIp,
			'net2' => $this->currentNet,
			'family' => $this->family,
			'switches' => $this->switches,
			'first' => $this->firstSwitchAt,
			'last' => $this->at,
		];
	}
}
