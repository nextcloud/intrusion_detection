<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

/**
 * What the app knows about one list's downloads: the version readers use,
 * and the outcome of the last attempts.
 */
final class ListState {
	/**
	 * @param ?int $version the complete version readers use; null before the first successful sync
	 * @param ?int $previous the version before, kept a few minutes for readers that started earlier
	 * @param ?string $error code of the last failure, null after a success
	 * @param int $failures failed attempts since the last success
	 * @param ?string $url the address the conditional request headers belong to
	 */
	public function __construct(
		public ?int $version = null,
		public ?int $previous = null,
		public ?int $switchedAt = null,
		public int $ranges = 0,
		public int $entries = 0,
		public int $skipped = 0,
		public int $malformed = 0,
		public ?int $firstAttemptAt = null,
		public ?int $attemptAt = null,
		public ?int $successAt = null,
		public ?int $failureAt = null,
		public ?string $error = null,
		public int $failures = 0,
		public ?string $url = null,
		public ?string $lastModified = null,
		public ?string $etag = null,
	) {
	}

	public function hasFailedSinceSuccess(): bool {
		return $this->failureAt !== null && ($this->successAt === null || $this->failureAt > $this->successAt);
	}

	/**
	 * Whether the list has not synced successfully for more than three of its
	 * intervals, counted from the last success or, without one, from the
	 * first attempt.
	 */
	public function isStale(int $interval, int $now): bool {
		if (!$this->hasFailedSinceSuccess()) {
			return false;
		}
		$since = $this->successAt ?? $this->firstAttemptAt ?? $this->failureAt;
		return $since !== null && $now - $since > 3 * $interval;
	}

	/**
	 * @return array<string, int|string|null>
	 */
	public function toArray(): array {
		return [
			'version' => $this->version,
			'previous' => $this->previous,
			'switched_at' => $this->switchedAt,
			'ranges' => $this->ranges,
			'entries' => $this->entries,
			'skipped' => $this->skipped,
			'malformed' => $this->malformed,
			'first_attempt_at' => $this->firstAttemptAt,
			'attempt_at' => $this->attemptAt,
			'success_at' => $this->successAt,
			'failure_at' => $this->failureAt,
			'error' => $this->error,
			'failures' => $this->failures,
			'url' => $this->url,
			'last_modified' => $this->lastModified,
			'etag' => $this->etag,
		];
	}

	/**
	 * @param array<array-key, mixed> $data
	 */
	public static function fromArray(array $data): self {
		$int = static fn (string $key): ?int => is_int($data[$key] ?? null) ? $data[$key] : null;
		$string = static fn (string $key): ?string => is_string($data[$key] ?? null) ? $data[$key] : null;
		return new self(
			$int('version'),
			$int('previous'),
			$int('switched_at'),
			$int('ranges') ?? 0,
			$int('entries') ?? 0,
			$int('skipped') ?? 0,
			$int('malformed') ?? 0,
			$int('first_attempt_at'),
			$int('attempt_at'),
			$int('success_at'),
			$int('failure_at'),
			$string('error'),
			$int('failures') ?? 0,
			$string('url'),
			$string('last_modified'),
			$string('etag'),
		);
	}
}
