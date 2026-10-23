<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist\Parser;

use OCA\IntrusionDetection\Net\RangeCodec;

/**
 * What a parser read from a downloaded list.
 *
 * - `entries`: valid ranges in the file
 * - `malformed`: entries that are not a range
 * - `skipped`: valid ranges left out because they touch private or local
 *   address space ({@see RangeCodec::overlapsReserved()})
 *
 * A list over its entry limit is refused as soon as the limit is passed.
 */
final class ParsedList {
	/** @var list<string> compact ranges */
	public array $ranges = [];
	public int $entries = 0;
	public int $malformed = 0;
	public int $skipped = 0;

	/**
	 * @param int $maxEntries the most valid ranges the list may have
	 */
	public function __construct(
		private readonly int $maxEntries = PHP_INT_MAX,
	) {
	}

	/**
	 * @throws ListTooLongException at the first valid range over the limit
	 */
	public function add(string $candidate): void {
		try {
			$range = RangeCodec::parse($candidate);
		} catch (\InvalidArgumentException) {
			$this->malformed++;
			return;
		}
		if ($this->entries >= $this->maxEntries) {
			throw new ListTooLongException($this->maxEntries);
		}
		$this->entries++;
		if (RangeCodec::overlapsReserved($range['family'], $range['start'], $range['end'])) {
			$this->skipped++;
			return;
		}
		$this->ranges[] = $range['family'] . $range['start'] . $range['end'];
	}

	public function malformedShare(): float {
		$total = $this->entries + $this->malformed;
		return $total === 0 ? 0.0 : $this->malformed / $total;
	}
}
