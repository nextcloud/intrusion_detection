<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Address;

final class AddressFacts {
	/**
	 * @param list<string> $attributes
	 * @param bool $perAddress whether the facts hold for this IPv6 address only, not for its whole /64
	 */
	public function __construct(
		public readonly int $denyUntil = 0,
		public readonly string $reference = '',
		public readonly array $attributes = [],
		public readonly bool $perAddress = false,
	) {
	}
}
