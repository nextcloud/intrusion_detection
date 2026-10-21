<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

use OCP\IL10N;

/**
 * A timeline source that also has something to say about the report as a
 * whole, e.g. where to find records the report cannot include.
 */
interface IAddsReportNotes {
	/**
	 * @return list<ReportNote>
	 */
	public function notesFor(IncidentQuery $query, IL10N $l): array;
}
