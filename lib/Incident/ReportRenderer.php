<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

use OCA\IntrusionDetection\Admin\DetectionPresenter;
use OCA\IntrusionDetection\AppInfo\Application;
use OCP\IDateTimeFormatter;
use OCP\IDateTimeZone;
use OCP\IL10N;
use OCP\Template\ITemplateManager;

/**
 * Turns an incident report into a document: JSON for machines, or a
 * self-contained HTML page to print or save as PDF.
 *
 * The HTML page is rendered from `templates/incident-report.php`, which
 * escapes every value. It loads nothing: no script, no image, no font and
 * no style sheet from anywhere, and its own Content-Security-Policy says
 * so, also when the file is opened from disk.
 */
class ReportRenderer {
	public function __construct(
		private readonly ITemplateManager $templates,
		private readonly IDateTimeFormatter $formatter,
		private readonly IDateTimeZone $timeZone,
	) {
	}

	public function json(IncidentReport $report): string {
		// Tags and ampersands are escaped, so the document stays inert even if it is shown as HTML.
		return json_encode($report->toArray(), JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP) . "\n";
	}

	public function html(IncidentReport $report, IL10N $l): string {
		$template = $this->templates->getTemplate(Application::APP_ID, 'incident-report');
		foreach ($this->view($report, $l) as $key => $value) {
			$template->assign($key, $value);
		}
		return $template->fetchPage();
	}

	/**
	 * A file name that says what the report is about and when it was made,
	 * with nothing but letters, digits, dots and dashes.
	 */
	public function filename(IncidentReport $report, ReportFormat $format): string {
		$subject = strtolower((string)preg_replace('/[^A-Za-z0-9.]+/', '-', $report->query->subject()));
		$subject = trim(substr($subject, 0, 64), '-.');
		return 'incident-report-' . ($subject === '' ? $report->query->subjectType : $subject) . '-' . gmdate('Ymd-His', $report->generatedAt) . '.' . $format->extension();
	}

	/**
	 * Everything the template prints, as plain text. The template escapes it.
	 *
	 * @return array<string, mixed>
	 */
	public function view(IncidentReport $report, IL10N $l): array {
		$query = $report->query;
		$summary = $report->summary;
		$subject = $query->isUser()
			? ($report->displayName !== null && $report->displayName !== $query->uid
				? $l->t('Account %1$s (%2$s)', [(string)$query->uid, $report->displayName])
				: $l->t('Account %s', [(string)$query->uid]))
			: $l->t('Address %s', [$query->subject()]);
		$kindLabels = array_column($report->kinds, 'label', 'id');

		return [
			'language' => $l->getLanguageCode(),
			'title' => $l->t('Incident report: %s', [$subject]),
			'eyebrow' => $l->t('Nextcloud intrusion detection · Incident report'),
			'subject' => $subject,
			'meta' => [
				[$l->t('Period'), $l->t('%1$s to %2$s', [$this->dateTime($query->since, $l), $this->dateTime($query->until, $l)])],
				[$l->t('Generated'), $l->t('%1$s by %2$s', [$this->dateTime($report->generatedAt, $l), $report->generatedBy])],
				[$l->t('Server'), $report->server],
				[$l->t('Time zone'), $this->timeZone->getTimeZone($report->generatedAt)->getName()],
			],
			'summaryHeading' => $l->t('Summary'),
			'headline' => $summary->headline,
			'keyFacts' => [
				[$l->t('Started'), $summary->startedAt === null ? '–' : $this->dateTime($summary->startedAt, $l)],
				[$l->t('Found by Nextcloud'), $summary->foundAt === null ? '–' : $this->dateTime($summary->foundAt, $l)],
				[$l->t('Last activity'), $summary->lastActivityAt === null ? '–' : $this->dateTime($summary->lastActivityAt, $l)],
			],
			'sections' => [
				['heading' => $l->t('What happened'), 'items' => $summary->happened, 'empty' => $l->t('Nothing was recorded in this period.')],
				['heading' => $l->t('Who and what is involved'), 'items' => $summary->affected, 'empty' => '–'],
				['heading' => $l->t('Data that may be affected'), 'items' => $summary->dataCategories, 'empty' => $summary->dataNote ?? '–'],
				['heading' => $l->t('What was done'), 'items' => $summary->measures, 'empty' => $l->t('Nothing was done.')],
				['heading' => $l->t('Still open'), 'items' => $summary->openItems, 'empty' => $l->t('Nothing.')],
			],
			'timelineHeading' => $l->t('Timeline'),
			'truncated' => $report->truncated ? $l->t('Only the first %s entries of the period are included. Build reports for shorter periods to see the rest.', [(string)$report->maxEntries]) : null,
			'emptyTimeline' => $l->t('There are no entries for this period.'),
			'days' => $this->days($report->entries, $kindLabels, $l),
			'notesHeading' => $l->t('Notes'),
			'notes' => array_map(static fn (ReportNote $n): array => ['text' => $n->text, 'url' => $n->url, 'linkLabel' => $n->linkLabel ?? $n->url], $report->notes),
			'footer' => $l->t('This report was built on request from the records Nextcloud keeps, and it is not stored on the server. Times are in the time zone shown above. Report format version %s.', [(string)IncidentReport::SCHEMA_VERSION]),
		];
	}

	/**
	 * The entries grouped by day, each with its time and labels.
	 *
	 * @param list<TimelineEntry> $entries
	 * @param array<string, string> $kindLabels
	 * @return list<array{label: string, entries: list<array<string, mixed>>}>
	 */
	private function days(array $entries, array $kindLabels, IL10N $l): array {
		$days = [];
		$label = null;
		$dayEntries = [];
		foreach ($entries as $entry) {
			$day = $this->formatter->formatDate($entry->at, 'full', null, $l);
			if ($label !== null && $label !== $day) {
				$days[] = ['label' => $label, 'entries' => $dayEntries];
				$dayEntries = [];
			}
			$label = $day;
			$labels = [$kindLabels[$entry->kind] ?? $entry->kind];
			if ($entry->severity !== null) {
				$labels[] = $this->severity($entry->severity, $l);
			}
			if ($entry->outcome !== null) {
				$labels[] = DetectionPresenter::outcomeLabel($entry->outcome, $l);
			}
			$meta = [];
			if ($entry->lastSeenAt !== null) {
				$meta[] = $l->t('Last seen %s', [$this->dateTime($entry->lastSeenAt, $l)]);
			}
			if ($entry->endsAt !== null) {
				$meta[] = $l->t('Until %s', [$this->dateTime($entry->endsAt, $l)]);
			}
			if ($entry->address !== null) {
				$meta[] = $l->t('Address: %s', [$entry->address]);
			}
			if ($entry->accounts !== []) {
				$meta[] = $l->t('Accounts: %s', [implode(', ', $entry->accounts)]);
			}
			$reference = $entry->quotableReference();
			if ($reference !== null) {
				$meta[] = $l->t('Reference: %s', [$reference]);
			}
			$dayEntries[] = [
				'time' => $this->formatter->formatTime($entry->at, 'short', null, $l),
				'severity' => $entry->severity ?? 'none',
				'labels' => implode(' · ', $labels),
				'title' => $entry->title,
				'details' => $entry->details,
				'doneHeading' => $entry->enforced === false ? $l->t('What Nextcloud would have done') : $l->t('What Nextcloud did'),
				'done' => $entry->done,
				'note' => $entry->note,
				'meta' => $meta,
			];
		}
		if ($label !== null) {
			$days[] = ['label' => $label, 'entries' => $dayEntries];
		}
		return $days;
	}

	private function dateTime(int $timestamp, IL10N $l): string {
		return $this->formatter->formatDateTime($timestamp, 'long', 'short', null, $l);
	}

	private function severity(string $severity, IL10N $l): string {
		return match ($severity) {
			'low' => $l->t('Low'),
			'medium' => $l->t('Medium'),
			'high' => $l->t('High'),
			'critical' => $l->t('Critical'),
			default => $severity,
		};
	}
}
