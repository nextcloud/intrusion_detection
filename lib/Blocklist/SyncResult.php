<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

final class SyncResult {
	/** A new version was written and is now in use */
	public const UPDATED = 'updated';
	/** The publisher reported no change since the last download */
	public const UNCHANGED = 'unchanged';
	/** The download or the list was refused; the previous version stays in use */
	public const FAILED = 'failed';
	/** Another sync is running */
	public const SKIPPED = 'skipped';

	/**
	 * @param self::UPDATED|self::UNCHANGED|self::FAILED|self::SKIPPED $outcome
	 * @param ?string $error a {@see SyncFailure} code
	 * @param ?int $status the HTTP status of an HTTP failure
	 */
	public function __construct(
		public readonly string $listId,
		public readonly string $outcome,
		public readonly ?string $error = null,
		public readonly int $ranges = 0,
		public readonly ?int $status = null,
	) {
	}

	/**
	 * @return array{list: string, outcome: string, error: ?string, ranges: int}
	 */
	public function toArray(): array {
		return ['list' => $this->listId, 'outcome' => $this->outcome, 'error' => $this->error, 'ranges' => $this->ranges];
	}
}
