<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

/**
 * A built incident report. It exists only in memory, for the one request
 * or command that asked for it.
 */
final class IncidentReport {
	/** Raised whenever the JSON changes in a way readers must know about */
	public const SCHEMA_VERSION = 1;

	/**
	 * @param list<TimelineEntry> $entries oldest first
	 * @param list<array{id: string, label: string, count: int}> $kinds every kind the sources know, with the number of entries
	 * @param list<ReportNote> $notes
	 */
	public function __construct(
		public readonly IncidentQuery $query,
		public readonly ?string $displayName,
		public readonly int $generatedAt,
		public readonly string $generatedBy,
		public readonly string $server,
		public readonly ReportSummary $summary,
		public readonly array $entries,
		public readonly array $kinds,
		public readonly array $notes,
		public readonly bool $truncated,
		public readonly int $maxEntries,
	) {
	}

	/**
	 * @return array{schemaVersion: int, generatedAt: int, generatedBy: string, server: string, subject: array{type: string, value: string, displayName: ?string}, period: array{since: int, until: int}, summary: array{headline: string, happened: list<string>, startedAt: ?int, foundAt: ?int, lastActivityAt: ?int, affected: list<string>, dataCategories: list<string>, dataNote: ?string, measures: list<string>, openItems: list<string>, counts: array{entries: int, detections: int, enforced: int, acted: int, observed: int}}, kinds: list<array{id: string, label: string, count: int}>, entries: list<array{id: string, at: int, endsAt: ?int, lastSeenAt: ?int, kind: string, group: string, title: string, severity: ?string, enforced: ?bool, outcome: 'acted'|'notified'|'recorded'|'observed'|null, details: list<string>, done: list<string>, note: ?string, address: ?string, accounts: list<string>, ref: ?array{type: string, id: string}}>, notes: list<array{id: string, text: string, url: ?string, linkLabel: ?string}>, truncated: bool, maxEntries: int}
	 */
	public function toArray(): array {
		return [
			'schemaVersion' => self::SCHEMA_VERSION,
			'generatedAt' => $this->generatedAt,
			'generatedBy' => $this->generatedBy,
			'server' => $this->server,
			'subject' => [
				'type' => $this->query->subjectType,
				'value' => $this->query->subject(),
				'displayName' => $this->displayName,
			],
			'period' => ['since' => $this->query->since, 'until' => $this->query->until],
			'summary' => $this->summary->toArray(),
			'kinds' => $this->kinds,
			'entries' => array_map(static fn (TimelineEntry $e): array => $e->toArray(), $this->entries),
			'notes' => array_map(static fn (ReportNote $n): array => $n->toArray(), $this->notes),
			'truncated' => $this->truncated,
			'maxEntries' => $this->maxEntries,
		];
	}
}
