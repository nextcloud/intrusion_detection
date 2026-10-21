<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

/**
 * What happened in one digest period, independent of the reader's
 * language. {@see Digest} collects it and turns it into an email.
 *
 * Lists are empty when there is nothing to report, and their sections are
 * left out of the email then.
 */
final class DigestReport {
	/**
	 * @param 'daily'|'weekly' $kind
	 * @param 'protecting'|'learning'|'off' $state
	 * @param array{protect: int, observe: int, off: int} $modes configured checks per effective mode
	 * @param array<string, array{enforced: int, observed: int, previous: int}> $checks per check id, sorted by detections in the period
	 * @param list<array{ip: string, detections: int, checks: list<string>, bans: int}> $sources
	 * @param list<array{uid: string, detections: int}> $accounts accounts under attack
	 * @param list<array{label: string, detections: int, addresses: int, lastAt: int}> $decoys decoys that were used
	 * @param list<array{shareId: int, owner: ?string, detections: int}> $shares shares under attack
	 * @param list<array{id: string, name: string, matches: int}> $blocklists lookups of addresses on each list
	 * @param list<array{uid: string, until: int}> $protectedAccounts accounts that need extra confirmation right now
	 * @param list<array{id: int, uid: string, checkId: string, verdictAt: int}> $deniedByUsers detections their account answered with "This was not me"
	 */
	public function __construct(
		public readonly string $kind,
		public readonly int $start,
		public readonly int $end,
		public readonly int $previousStart,
		public readonly string $state,
		public readonly int $learningDaysLeft,
		public readonly array $modes,
		public readonly array $checks,
		public readonly int $enforced,
		public readonly int $observed,
		public readonly int $previousDetections,
		public readonly int $bans,
		public readonly array $sources,
		public readonly array $accounts,
		public readonly array $decoys,
		public readonly array $shares,
		public readonly array $blocklists,
		public readonly array $protectedAccounts,
		public readonly array $deniedByUsers,
	) {
	}

	public function detections(): int {
		return $this->enforced + $this->observed;
	}

	public function blocklistMatches(): int {
		return array_sum(array_column($this->blocklists, 'matches'));
	}

	/**
	 * Nothing happened in the period: no detection, no block, no blocklist match.
	 */
	public function isQuiet(): bool {
		return $this->detections() === 0 && $this->bans === 0 && $this->blocklistMatches() === 0;
	}
}
