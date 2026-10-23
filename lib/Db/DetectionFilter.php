<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

final class DetectionFilter {
	/**
	 * @param list<string> $checkIds
	 * @param list<string> $severities
	 */
	public function __construct(
		public readonly array $checkIds = [],
		public readonly array $severities = [],
		public readonly ?string $uid = null,
		public readonly ?string $ip = null,
		public readonly ?bool $enforced = null,
		public readonly ?int $since = null,
		public readonly ?int $until = null,
		public readonly int $limit = 50,
		public readonly int $offset = 0,
		/** Only detections with a higher id, i.e. newer ones */
		public readonly ?string $afterId = null,
		/** Only detections the user answered "Was this you?" for (true), or did not (false) */
		public readonly ?bool $answered = null,
	) {
	}
}
