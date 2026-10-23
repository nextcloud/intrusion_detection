<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

/**
 * Merges the facts of a repeated hit into the facts of the detection it
 * joins, so that the detection still explains every hit. A check's facts
 * class declares how its facts merge ({@see IMergeableFacts}); facts
 * without a class merge by the shape of their values ({@see self::byShape()}).
 */
final class FactsMerger {
	public const MAX_LIST = 50;

	/**
	 * @param array<array-key, mixed> $stored the facts of the stored detection
	 * @return array<array-key, mixed>
	 */
	public static function merge(array $stored, DetectionDraft $draft): array {
		return $draft->typedFacts instanceof IMergeableFacts
			? $draft->typedFacts->mergedOnto($stored)
			: self::byShape($stored, Explanation::facts($draft));
	}

	/**
	 * - `rule` stays as it was: it says what the detection is about;
	 * - `first` keeps the earliest time, `last` the latest;
	 * - lists (accounts in `targets`, rules, network lists …) are joined, in
	 *   the order they were first seen, `targets` to at most
	 *   {@see Explanation::MAX_TARGETS} entries and other lists to MAX_LIST;
	 * - everything else (counts within the window, the latest address, the
	 *   risk score …) takes the value of the latest hit.
	 *
	 * @param array<array-key, mixed> $old
	 * @param array<array-key, mixed> $new
	 * @return array<array-key, mixed>
	 */
	public static function byShape(array $old, array $new): array {
		$merged = $old;
		foreach ($new as $key => $value) {
			$previous = $old[$key] ?? null;
			$merged[$key] = match (true) {
				$previous === null => $value,
				$key === 'rule' => $previous,
				$key === 'first' && is_int($previous) && is_int($value) => min($previous, $value),
				$key === 'last' && is_int($previous) && is_int($value) => max($previous, $value),
				is_array($previous) && is_array($value) && array_is_list($previous) && array_is_list($value)
					=> self::union($previous, $value, $key === 'targets' ? Explanation::MAX_TARGETS : self::MAX_LIST),
				default => $value,
			};
		}
		return $merged;
	}

	/**
	 * Two lists joined in the order their items were first seen, without
	 * repeats, to at most `$max` items. A missing list is no list.
	 *
	 * @param ?list<mixed> $old
	 * @param ?list<mixed> $new
	 * @return ?list<mixed>
	 */
	public static function union(?array $old, ?array $new, int $max = self::MAX_LIST): ?array {
		if ($old === null || $new === null) {
			return $new ?? $old;
		}
		$seen = [];
		$union = [];
		foreach (array_merge($old, $new) as $item) {
			$key = is_scalar($item) ? gettype($item) . ':' . $item : json_encode($item);
			if ($key === false || isset($seen[$key])) {
				continue;
			}
			$seen[$key] = true;
			$union[] = $item;
			if (count($union) >= $max) {
				break;
			}
		}
		return $union;
	}
}
