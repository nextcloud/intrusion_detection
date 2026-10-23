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
 * class declares how its facts merge ({@see IMergeableFacts}); the facts of
 * a draft that declares nothing are those of the latest hit.
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
			: array_replace($stored, $draft->facts);
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
