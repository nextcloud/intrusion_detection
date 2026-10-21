<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Export;

use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Net\RangeCodec;

/**
 * One active block as the export writes it.
 */
final class ExportEntry {
	public function __construct(
		public readonly string $cidr,
		public readonly int $family,
		public readonly string $start,
		public readonly string $end,
		public readonly int $expiresAt,
		public readonly string $reference,
		public readonly int $level,
		public readonly string $checkId,
	) {
	}

	/**
	 * @throws \InvalidArgumentException when the stored range is not valid
	 */
	public static function fromBan(Ban $ban): self {
		$range = RangeCodec::parse($ban->getCidr());
		return new self(
			RangeCodec::format($range['family'], $range['start'], $range['end']),
			$range['family'],
			$range['start'],
			$range['end'],
			$ban->getExpiresAt(),
			$ban->getReference(),
			$ban->getLevel(),
			$ban->getCheckId(),
		);
	}

	/**
	 * Sort by family and address, larger ranges before the ranges they contain.
	 *
	 * @param list<self> $entries
	 * @return list<self>
	 */
	public static function sort(array $entries): array {
		usort($entries, static fn (self $a, self $b): int => [$a->family, $a->start, $b->end] <=> [$b->family, $b->start, $a->end]);
		return $entries;
	}

	/**
	 * Leave out entries inside an earlier one, for firewalls whose sets refuse
	 * overlapping ranges (nftables interval sets). The entries must be sorted.
	 *
	 * @param list<self> $sorted
	 * @return list<self>
	 */
	public static function withoutContained(array $sorted): array {
		$kept = [];
		$last = null;
		foreach ($sorted as $entry) {
			if ($last !== null && $last->family === $entry->family && strcmp($entry->end, $last->end) <= 0) {
				continue;
			}
			$kept[] = $entry;
			$last = $entry;
		}
		return $kept;
	}
}
