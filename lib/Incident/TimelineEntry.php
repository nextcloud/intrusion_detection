<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

/**
 * One event on the timeline of an incident report.
 *
 * Every text is plain, translated and complete; the renderers only escape
 * it. Entries carry identifiers (detection ids, ban references, token ids),
 * never a secret: no password, token, share token or fingerprint.
 *
 * `categories`, `followUp` and `measures` feed the summary and are not part
 * of the entry as exported.
 */
final class TimelineEntry {
	/**
	 * @param string $id unique within the report, e.g. "detection:42"
	 * @param string $kind what kind of event; the filters of the timeline use it
	 * @param string $group short label to count entries by in the summary, e.g. the check's name
	 * @param ?int $endsAt for events that lasted: when they were last seen
	 * @param ?string $severity low, medium, high or critical; null for events without one
	 * @param ?bool $enforced for detections: whether Nextcloud acted, or only observed
	 * @param list<string> $details what happened, sentence by sentence
	 * @param list<string> $done what Nextcloud did (or would have done)
	 * @param ?string $note why nothing was done, or another remark
	 * @param ?string $address the address involved, if any
	 * @param list<string> $accounts the accounts involved, if any
	 * @param ?array{type: string, id: string} $ref what the entry points to, e.g. a detection id
	 * @param list<DataCategory> $categories data that may have been affected, for the summary
	 * @param ?string $followUp something to check afterwards, for the summary's open items
	 * @param ?list<string> $measures what was really done, for the summary; null to take `$done` unless only observed
	 */
	public function __construct(
		public readonly string $id,
		public readonly int $at,
		public readonly string $kind,
		public readonly string $group,
		public readonly string $title,
		public readonly ?int $endsAt = null,
		public readonly ?string $severity = null,
		public readonly ?bool $enforced = null,
		public readonly array $details = [],
		public readonly array $done = [],
		public readonly ?string $note = null,
		public readonly ?string $address = null,
		public readonly array $accounts = [],
		public readonly ?array $ref = null,
		public readonly array $categories = [],
		public readonly ?string $followUp = null,
		public readonly ?array $measures = null,
	) {
	}

	/**
	 * @return array{id: string, at: int, endsAt: ?int, kind: string, group: string, title: string, severity: ?string, enforced: ?bool, details: list<string>, done: list<string>, note: ?string, address: ?string, accounts: list<string>, ref: ?array{type: string, id: string}}
	 */
	public function toArray(): array {
		return [
			'id' => $this->id,
			'at' => $this->at,
			'endsAt' => $this->endsAt,
			'kind' => $this->kind,
			'group' => $this->group,
			'title' => $this->title,
			'severity' => $this->severity,
			'enforced' => $this->enforced,
			'details' => $this->details,
			'done' => $this->done,
			'note' => $this->note,
			'address' => $this->address,
			'accounts' => $this->accounts,
			'ref' => $this->ref,
		];
	}
}
