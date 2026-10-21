<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

use OCP\IL10N;

/**
 * One kind of record an incident report merges into its timeline:
 * detections, blocks, app passwords, shares …
 *
 * Add a source by implementing this interface and appending the class to
 * {@see IncidentReportBuilder::SOURCES}. The report, its filters, the JSON,
 * the printable page and occ pick it up from there.
 *
 * A source only reads. It never writes a row, a file or a cache entry, and
 * never returns a secret.
 */
interface ITimelineSource {
	/**
	 * The kinds of entries this source returns, with the label of each, for
	 * the filters of the timeline.
	 *
	 * @return array<string, string> kind => label
	 */
	public function kinds(IL10N $l): array;

	/**
	 * The entries for the query's account or address that fall into its
	 * period, oldest first, at most `$query->limit` of them.
	 *
	 * @return iterable<TimelineEntry>
	 */
	public function entriesFor(IncidentQuery $query, IL10N $l): iterable;
}
