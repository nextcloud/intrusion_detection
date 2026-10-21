<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Traps;

use OCA\IntrusionDetection\Net\SourceKey;

/**
 * A request for a trap URL, as the trap check records it.
 */
final class PendingTrapHit {
	/**
	 * @param array{path: string, trap: string, method: string} $facts
	 * @param bool $lure the request is a possible lure ({@see \OCA\IntrusionDetection\Net\FetchMetadata})
	 */
	public function __construct(
		public readonly SourceKey $source,
		public readonly array $facts,
		public readonly ?string $userAgent,
		public readonly bool $lure,
	) {
	}
}
