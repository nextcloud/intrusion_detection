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
		return self::fromRow([
			'cidr' => $ban->getCidr(),
			'expires_at' => $ban->getExpiresAt(),
			'reference' => $ban->getReference(),
			'level' => $ban->getLevel(),
			'check_id' => $ban->getCheckId(),
		]);
	}

	/**
	 * @param array{cidr: string, expires_at: int, reference: string, level: int, check_id: string} $row
	 * @throws \InvalidArgumentException when the stored range is not valid
	 */
	public static function fromRow(array $row): self {
		$range = RangeCodec::parse($row['cidr']);
		return new self(
			RangeCodec::format($range['family'], $range['start'], $range['end']),
			$range['family'],
			$range['start'],
			$range['end'],
			$row['expires_at'],
			$row['reference'],
			$row['level'],
			$row['check_id'],
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
	 * The blocks as ranges that do not overlap, for firewalls whose sets
	 * refuse overlapping ranges (nftables interval sets), with the protected
	 * ranges (loopback, the server, the allowlist) cut out.
	 *
	 * Every address keeps the block that lasts longest of those covering it:
	 * an address blocked longer than its /24 stays blocked when the /24 ends.
	 * Blocks are CIDR ranges, so two of them are either nested or apart; the
	 * pieces are written as CIDR ranges again.
	 *
	 * @param list<self> $sorted sorted ({@see self::sort()})
	 * @param list<array{0: int, 1: string, 2: string}> $protected family, first and last address, sorted and merged
	 * @return list<self>
	 */
	public static function disjoint(array $sorted, array $protected = []): array {
		$segments = [];
		// Open blocks, outermost first. A block that ends no later than the one
		// around it is painted by that one ("owner"); one that lasts longer is
		// a hole in its owner and paints itself.
		/** @var list<array{entry: self, winner: self, owner: int, holes: list<self>}> $stack */
		$stack = [];
		$close = static function (array $node) use (&$segments): void {
			$next = $node['entry']->start;
			foreach ($node['holes'] as $hole) {
				if (strcmp($next, $hole->start) < 0) {
					$segments[] = [$node['winner'], $next, (string)self::predecessor($hole->start)];
				}
				$next = RangeCodec::successor($hole->end);
				if ($next === null) {
					return;
				}
			}
			if (strcmp($next, $node['entry']->end) <= 0) {
				$segments[] = [$node['winner'], $next, $node['entry']->end];
			}
		};
		foreach ($sorted as $entry) {
			while ($stack !== [] && !self::contains($stack[count($stack) - 1]['entry'], $entry)) {
				$node = array_pop($stack);
				if ($node['owner'] === count($stack)) {
					$close($node);
				}
			}
			$top = $stack === [] ? null : $stack[count($stack) - 1];
			if ($top !== null && $top['winner']->expiresAt >= $entry->expiresAt) {
				$stack[] = ['entry' => $entry, 'winner' => $top['winner'], 'owner' => $top['owner'], 'holes' => []];
				continue;
			}
			if ($top !== null) {
				$stack[$top['owner']]['holes'][] = $entry;
			}
			$stack[] = ['entry' => $entry, 'winner' => $entry, 'owner' => count($stack), 'holes' => []];
		}
		while ($stack !== []) {
			$node = array_pop($stack);
			if ($node['owner'] === count($stack)) {
				$close($node);
			}
		}
		usort($segments, static fn (array $a, array $b): int => [$a[0]->family, $a[1]] <=> [$b[0]->family, $b[1]]);

		$pieces = [];
		foreach ($segments as [$winner, $start, $end]) {
			foreach (self::withoutProtected($winner->family, $start, $end, $protected) as [$from, $to]) {
				foreach (self::cidrs($winner->family, $from, $to) as [$first, $last]) {
					$pieces[] = new self(RangeCodec::format($winner->family, $first, $last), $winner->family, $first, $last, $winner->expiresAt, $winner->reference, $winner->level, $winner->checkId);
				}
			}
		}
		return $pieces;
	}

	private static function contains(self $outer, self $inner): bool {
		return $outer->family === $inner->family && strcmp($outer->start, $inner->start) <= 0 && strcmp($inner->end, $outer->end) <= 0;
	}

	/**
	 * @param list<array{0: int, 1: string, 2: string}> $protected
	 * @return list<array{0: string, 1: string}>
	 */
	private static function withoutProtected(int $family, string $start, string $end, array $protected): array {
		$parts = [];
		foreach ($protected as [$protectedFamily, $protectedStart, $protectedEnd]) {
			if ($protectedFamily !== $family || strcmp($protectedEnd, $start) < 0) {
				continue;
			}
			if (strcmp($protectedStart, $end) > 0) {
				break;
			}
			if (strcmp($start, $protectedStart) < 0) {
				$parts[] = [$start, (string)self::predecessor($protectedStart)];
			}
			$next = RangeCodec::successor($protectedEnd);
			if ($next === null || strcmp($next, $end) > 0) {
				return $parts;
			}
			$start = $next;
		}
		$parts[] = [$start, $end];
		return $parts;
	}

	/**
	 * The fewest CIDR ranges that make up a range.
	 *
	 * @return list<array{0: string, 1: string}>
	 */
	private static function cidrs(int $family, string $start, string $end): array {
		$ranges = [];
		$first = (string)hex2bin($start);
		$last = (string)hex2bin($end);
		while (true) {
			for ($prefix = $family === 4 ? 96 : 0; $prefix <= 128; $prefix++) {
				$mask = self::mask($prefix);
				if (($first & $mask) === $first && strcmp($first | ~$mask, $last) <= 0) {
					break;
				}
			}
			$blockEnd = $first | ~self::mask($prefix);
			$ranges[] = [bin2hex($first), bin2hex($blockEnd)];
			$next = RangeCodec::successor(bin2hex($blockEnd));
			if ($next === null || strcmp($blockEnd, $last) >= 0) {
				return $ranges;
			}
			$first = (string)hex2bin($next);
		}
	}

	/**
	 * The address before the given one; null before the very first address.
	 */
	private static function predecessor(string $hex): ?string {
		$bytes = (string)hex2bin($hex);
		for ($i = 15; $i >= 0; $i--) {
			$byte = ord($bytes[$i]);
			if ($byte > 0) {
				$bytes[$i] = chr($byte - 1);
				return bin2hex($bytes);
			}
			$bytes[$i] = "\xff";
		}
		return null;
	}

	/**
	 * 16-byte network mask for a prefix length of 0 to 128.
	 */
	private static function mask(int $prefix): string {
		$mask = str_repeat("\xff", intdiv($prefix, 8));
		if ($prefix % 8 !== 0) {
			$mask .= chr((0xff << (8 - $prefix % 8)) & 0xff);
		}
		return str_pad($mask, 16, "\0");
	}
}
