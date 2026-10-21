<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Risk;

/**
 * Why a password login counts as coming from a risky network.
 */
final class RiskyLogin {
	/**
	 * @param list<string> $attributes `tor` and/or `hosting`
	 * @param list<string> $lists the ids of the network lists the address is on
	 */
	public function __construct(
		public readonly array $attributes,
		public readonly array $lists,
	) {
	}

	public function isTor(): bool {
		return in_array('tor', $this->attributes, true);
	}
}
