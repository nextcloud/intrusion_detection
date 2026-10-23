<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist\Parser;

/**
 * The downloaded list has more entries than a list may have. Parsing stops
 * at the first entry over the limit, so a huge list is never held in memory.
 */
class ListTooLongException extends \RuntimeException {
	public function __construct(
		public readonly int $maxEntries,
	) {
		parent::__construct('more than ' . $maxEntries . ' entries');
	}
}
