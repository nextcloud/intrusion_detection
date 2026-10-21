<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

/**
 * The outcome of the contribution runs, in the app config value `contribute_state`.
 */
final class ContributionState {
	public const RESULT_SENT = 'sent';
	public const RESULT_NOTHING = 'nothing';
	public const RESULT_FAILED = 'failed';

	/**
	 * @param ?int $windowEnd the next window starts after it: the end of the last window sent (or with nothing to send), or, before any success, the start of the first window
	 * @param ?string $result one of the RESULT_* constants
	 * @param ?string $error code of the last failure, null after a success
	 * @param int $reports reports sent by the last successful run
	 */
	public function __construct(
		public ?int $attemptAt = null,
		public ?int $successAt = null,
		public ?int $windowEnd = null,
		public ?string $result = null,
		public ?string $error = null,
		public int $reports = 0,
	) {
	}

	/**
	 * @return array{attempt_at: ?int, success_at: ?int, window_end: ?int, result: ?string, error: ?string, reports: int}
	 */
	public function toArray(): array {
		return [
			'attempt_at' => $this->attemptAt,
			'success_at' => $this->successAt,
			'window_end' => $this->windowEnd,
			'result' => $this->result,
			'error' => $this->error,
			'reports' => $this->reports,
		];
	}

	/**
	 * @param array<array-key, mixed> $data
	 */
	public static function fromArray(array $data): self {
		$int = static fn (string $key): ?int => is_int($data[$key] ?? null) ? $data[$key] : null;
		$string = static fn (string $key): ?string => is_string($data[$key] ?? null) ? $data[$key] : null;
		return new self($int('attempt_at'), $int('success_at'), $int('window_end'), $string('result'), $string('error'), $int('reports') ?? 0);
	}
}
