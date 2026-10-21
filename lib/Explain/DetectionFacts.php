<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCA\IntrusionDetection\Db\Detection;
use OCP\IL10N;

/**
 * Typed access to what a stored detection recorded: its facts and the
 * thresholds that were in force when it was made. Narratives read these,
 * never the current settings, so they keep explaining what happened then.
 */
final class DetectionFacts {
	/**
	 * @param array<array-key, mixed> $facts
	 * @param array<array-key, mixed> $thresholds
	 */
	private function __construct(
		private readonly array $facts,
		private readonly array $thresholds,
		public readonly int $first,
		public readonly int $last,
	) {
	}

	public static function of(Detection $detection): self {
		$explanation = $detection->getExplanationData();
		return new self(
			is_array($explanation['facts'] ?? null) ? $explanation['facts'] : [],
			is_array($explanation['thresholds'] ?? null) ? $explanation['thresholds'] : [],
			(int)($explanation['facts']['first'] ?? $explanation['first'] ?? $detection->getCreatedAt()),
			(int)($explanation['facts']['last'] ?? $explanation['last'] ?? $detection->getLastSeenAt()),
		);
	}

	public function int(string $key, int $default = 0): int {
		$value = $this->facts[$key] ?? null;
		return is_int($value) ? $value : (is_numeric($value) ? (int)$value : $default);
	}

	public function string(string $key, string $default = ''): string {
		$value = $this->facts[$key] ?? null;
		return is_string($value) ? $value : $default;
	}

	public function bool(string $key): bool {
		return ($this->facts[$key] ?? false) === true;
	}

	/**
	 * @return list<string>
	 */
	public function list(string $key): array {
		$value = $this->facts[$key] ?? null;
		return is_array($value) ? array_values(array_map('strval', array_filter($value, 'is_scalar'))) : [];
	}

	public function threshold(string $key, int $default = 0): int {
		$value = $this->thresholds[$key] ?? null;
		return is_int($value) ? $value : (is_numeric($value) ? (int)$value : $default);
	}

	/**
	 * "3 of them exist: alice, bob, carol." for the accounts an attack tried,
	 * or null when none of them exists.
	 */
	public function targetsSentence(IL10N $l, string $key = 'targets'): ?string {
		$targets = $this->list($key);
		if ($targets === []) {
			return null;
		}
		return $l->n('%n of them exists: %s.', '%n of them exist: %s.', count($targets), [implode(', ', $targets)]);
	}
}
