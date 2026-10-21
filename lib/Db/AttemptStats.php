<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

/**
 * Counts over a set of failed attempts.
 *
 * `failures` and `distinctNames` count the stored rows. While a flood was
 * sampled, one stored row stands for several attempts (its weight); the
 * estimates scale each row by its weight, and `maxWeight` is the largest
 * weight among the rows (1 when nothing was sampled).
 */
final class AttemptStats {
	public function __construct(
		public readonly int $failures = 0,
		public readonly int $distinctNames = 0,
		public readonly int $distinctSources = 0,
		public readonly int $distinctUsers = 0,
		public readonly int $first = 0,
		public readonly int $last = 0,
		private readonly ?int $estimatedFailures = null,
		private readonly ?int $estimatedNames = null,
		public readonly int $maxWeight = 1,
	) {
	}

	/**
	 * How many attempts the rows stand for.
	 */
	public function failuresEstimate(): int {
		return $this->estimatedFailures ?? $this->failures;
	}

	/**
	 * How many different names (inputs, tokens) the rows stand for.
	 */
	public function namesEstimate(): int {
		return $this->estimatedNames ?? $this->distinctNames;
	}
}
