<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

/**
 * What one response did. `ref` holds identifiers (ban ids, token ids) that
 * explain the action later; never secrets.
 */
final class ResponseOutcome {
	public const NOTE_UNAVAILABLE = 'unavailable';
	public const NOTE_FAILED = 'failed';
	public const NOTE_NOTHING_TO_DO = 'nothing_to_do';

	public function __construct(
		public readonly bool $enforced,
		public readonly mixed $ref = null,
		public readonly ?string $note = null,
	) {
	}

	public static function done(mixed $ref = null, ?string $note = null): self {
		return new self(true, $ref, $note);
	}

	public static function skipped(string $note, mixed $ref = null): self {
		return new self(false, $ref, $note);
	}
}
