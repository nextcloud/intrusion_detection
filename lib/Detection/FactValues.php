<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

/**
 * Reads one stored fact for a facts class's `fromArray()`: null when the
 * fact is missing or not of the type, so rows written before a fact
 * existed read like rows without it.
 */
final class FactValues {
	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function int(array $stored, string $key): ?int {
		$value = $stored[$key] ?? null;
		return is_int($value) ? $value : (is_numeric($value) ? (int)$value : null);
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function string(array $stored, string $key): ?string {
		$value = $stored[$key] ?? null;
		return is_string($value) ? $value : null;
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function bool(array $stored, string $key): ?bool {
		$value = $stored[$key] ?? null;
		return is_bool($value) ? $value : null;
	}

	/**
	 * @param array<array-key, mixed> $stored
	 * @return ?list<string>
	 */
	public static function strings(array $stored, string $key): ?array {
		$value = $stored[$key] ?? null;
		return is_array($value) ? array_values(array_map('strval', array_filter($value, 'is_scalar'))) : null;
	}

	/**
	 * @param array<array-key, mixed> $stored
	 * @return ?list<int>
	 */
	public static function ints(array $stored, string $key): ?array {
		$value = $stored[$key] ?? null;
		return is_array($value) ? array_values(array_filter($value, 'is_int')) : null;
	}

	/**
	 * @param array<array-key, mixed> $stored
	 * @return ?array<array-key, mixed>
	 */
	public static function array(array $stored, string $key): ?array {
		$value = $stored[$key] ?? null;
		return is_array($value) ? $value : null;
	}

	/**
	 * The facts that were recorded: those whose value is not null.
	 *
	 * @param array<string, mixed> $values
	 * @return array<string, mixed>
	 */
	public static function recorded(array $values): array {
		return array_filter($values, static fn (mixed $value): bool => $value !== null);
	}
}
