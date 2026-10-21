<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident\Sources;

use OCA\IntrusionDetection\Incident\IAddsReportNotes;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\ITimelineSource;
use OCA\IntrusionDetection\Incident\ReportNote;
use OCP\App\IAppManager;
use OCP\IL10N;
use OCP\IURLGenerator;

/**
 * Where to find file actions, which the report cannot include.
 *
 * `OCP\Activity\IManager` only publishes activities; there is no public
 * interface to read them, and the Activity app shows each account only its
 * own stream. So this source adds no entries: it tells the reader where to
 * look instead (the account's Activity stream, and the audit log).
 */
class ActivitySource implements ITimelineSource, IAddsReportNotes {
	public function __construct(
		private readonly IAppManager $appManager,
		private readonly IURLGenerator $urlGenerator,
	) {
	}

	#[\Override]
	public function kinds(IL10N $l): array {
		return [];
	}

	#[\Override]
	public function entriesFor(IncidentQuery $query, IL10N $l): iterable {
		return [];
	}

	#[\Override]
	public function notesFor(IncidentQuery $query, IL10N $l): array {
		$notes = [];
		if (!$query->isUser()) {
			$notes[] = new ReportNote('file_actions', $l->t('File actions are recorded per account, not per address, so they are not part of this report. Build a report for each account involved to see where to find them.'));
		} elseif ($this->appManager->isEnabledForAnyone('activity')) {
			$notes[] = new ReportNote(
				'file_actions',
				$l->t('File actions are not part of this report: the Activity app keeps them, and it shows each person only their own activity. Ask the account owner to review their activity stream for this period.'),
				$this->urlGenerator->getAbsoluteURL('/index.php/apps/activity/'),
				$l->t('Activity stream'),
			);
		} else {
			$notes[] = new ReportNote('file_actions', $l->t('File actions are not part of this report, and the Activity app, which would record them, is not enabled.'));
		}
		if ($this->appManager->isEnabledForAnyone('admin_audit')) {
			$notes[] = new ReportNote('audit_log', $l->t('The audit log of the Auditing app records file actions with the account and the address. Search it for this period.'));
		}
		return $notes;
	}
}
