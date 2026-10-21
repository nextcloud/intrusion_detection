<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

/**
 * The summary at the top of an incident report, shaped like a breach
 * notification: what happened and when it started, when it was found,
 * who and what was affected, which data may be affected, what was done,
 * and what is still open.
 */
final class ReportSummary {
	/**
	 * @param list<string> $happened one line per kind of event, with counts
	 * @param list<string> $affected the accounts and addresses involved
	 * @param list<string> $dataCategories data that may be affected
	 * @param ?string $dataNote what the absence of data categories means, when there are none
	 * @param list<string> $measures what Nextcloud and the administrators did
	 * @param list<string> $openItems what to check or decide next
	 * @param array{entries: int, detections: int, enforced: int, observed: int} $counts
	 */
	public function __construct(
		public readonly string $headline,
		public readonly array $happened,
		public readonly ?int $startedAt,
		public readonly ?int $foundAt,
		public readonly ?int $lastActivityAt,
		public readonly array $affected,
		public readonly array $dataCategories,
		public readonly ?string $dataNote,
		public readonly array $measures,
		public readonly array $openItems,
		public readonly array $counts,
	) {
	}

	/**
	 * @return array{headline: string, happened: list<string>, startedAt: ?int, foundAt: ?int, lastActivityAt: ?int, affected: list<string>, dataCategories: list<string>, dataNote: ?string, measures: list<string>, openItems: list<string>, counts: array{entries: int, detections: int, enforced: int, observed: int}}
	 */
	public function toArray(): array {
		return [
			'headline' => $this->headline,
			'happened' => $this->happened,
			'startedAt' => $this->startedAt,
			'foundAt' => $this->foundAt,
			'lastActivityAt' => $this->lastActivityAt,
			'affected' => $this->affected,
			'dataCategories' => $this->dataCategories,
			'dataNote' => $this->dataNote,
			'measures' => $this->measures,
			'openItems' => $this->openItems,
			'counts' => $this->counts,
		];
	}
}
