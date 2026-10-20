<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

/**
 * Counts over a set of failed attempts.
 */
final class AttemptStats {
	public function __construct(
		public readonly int $failures = 0,
		public readonly int $distinctNames = 0,
		public readonly int $distinctSources = 0,
		public readonly int $distinctUsers = 0,
		public readonly int $first = 0,
		public readonly int $last = 0,
	) {
	}
}
