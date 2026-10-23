<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

use OCA\IntrusionDetection\Net\SourceKey;

/**
 * A block a check wanted was held back: many people log in from the
 * address, or it looks like a reverse proxy missing from trusted_proxies.
 */
final class BlockHeldBack implements ISignal {
	/**
	 * @param int $users how many people log in from it
	 * @param string $wantedBy the check that wanted to block it
	 * @param bool $proxy whether it looks like a reverse proxy without trusted_proxies
	 */
	public function __construct(
		public readonly SourceKey $target,
		public readonly int $users,
		public readonly string $wantedBy,
		public readonly bool $proxy,
	) {
	}
}
