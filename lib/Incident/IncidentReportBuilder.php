<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Incident\Sources\ActivitySource;
use OCA\IntrusionDetection\Incident\Sources\AdminChangeSource;
use OCA\IntrusionDetection\Incident\Sources\AppPasswordSource;
use OCA\IntrusionDetection\Incident\Sources\BanSource;
use OCA\IntrusionDetection\Incident\Sources\DetectionSource;
use OCA\IntrusionDetection\Incident\Sources\LoginSource;
use OCA\IntrusionDetection\Incident\Sources\SecurityChangeSource;
use OCA\IntrusionDetection\Incident\Sources\ShareSource;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\IUserManager;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Builds the incident report of section 16.6 of the concept: one timeline
 * for an account or an address over a period, merged from every source,
 * and a summary on top.
 *
 * The report is built in memory for the request that asks for it and
 * never stored. It holds at most {@see self::MAX_ENTRIES} entries: the
 * oldest ones of the period. When more exist it is marked truncated, and
 * the entries it holds are still complete up to the last of them.
 */
class IncidentReportBuilder {
	/** The most entries one report holds */
	public const MAX_ENTRIES = 2000;
	/** The most lines of measures the summary lists */
	private const MAX_MEASURES = 30;
	/** The most accounts or addresses the summary names */
	private const MAX_NAMES = 10;

	/**
	 * The sources, in the order entries of the same second are listed.
	 *
	 * Parts of the app that record more events, such as the login history
	 * and the security change log, add their source here.
	 */
	public const SOURCES = [
		DetectionSource::class,
		BanSource::class,
		AppPasswordSource::class,
		AdminChangeSource::class,
		ShareSource::class,
		ActivitySource::class,
		LoginSource::class,
		SecurityChangeSource::class,
	];

	public function __construct(
		private readonly ContainerInterface $container,
		private readonly IUserManager $userManager,
		private readonly IURLGenerator $urlGenerator,
		private readonly ITimeFactory $timeFactory,
		private readonly DateFormatter $dates,
		private readonly LoggerInterface $logger,
		private readonly int $maxEntries = self::MAX_ENTRIES,
	) {
	}

	public function build(IncidentQuery $query, string $generatedBy, IL10N $l): IncidentReport {
		// One more than fits tells whether the report is complete.
		$query = $query->withLimit($this->maxEntries + 1);
		$entries = [];
		$kinds = [];
		$notes = [];
		foreach ($this->sources() as $source) {
			$kinds += $source->kinds($l);
			try {
				$count = 0;
				foreach ($source->entriesFor($query, $l) as $entry) {
					if (++$count > $query->limit) {
						break;
					}
					$entries[] = $entry;
				}
				if ($source instanceof IAddsReportNotes) {
					array_push($notes, ...$source->notesFor($query, $l));
				}
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not read {source} for an incident report', ['source' => $source::class, 'exception' => $e]);
				$notes[] = new ReportNote('source_failed', $l->t('Some records could not be read (%s), so they are missing from this report. The server log has the details.', [implode(', ', $source->kinds($l))]));
			}
		}

		// The sort is stable: entries of the same second keep the order of the sources.
		usort($entries, static fn (TimelineEntry $a, TimelineEntry $b): int => $a->at <=> $b->at);
		$truncated = count($entries) > $this->maxEntries;
		$entries = array_slice($entries, 0, $this->maxEntries);

		$counted = array_count_values(array_map(static fn (TimelineEntry $e): string => $e->kind, $entries));
		$kindList = [];
		foreach ($kinds as $id => $label) {
			$kindList[] = ['id' => $id, 'label' => $label, 'count' => $counted[$id] ?? 0];
		}

		return new IncidentReport(
			$query,
			$query->uid !== null ? $this->userManager->get($query->uid)?->getDisplayName() : null,
			$this->timeFactory->getTime(),
			$generatedBy,
			$this->urlGenerator->getBaseUrl(),
			$this->summarise($query, $entries, $truncated, $l),
			$entries,
			$kindList,
			$notes,
			$truncated,
			$this->maxEntries,
		);
	}

	/**
	 * @return list<ITimelineSource>
	 */
	private function sources(): array {
		return array_map(fn (string $class): ITimelineSource => $this->container->get($class), self::SOURCES);
	}

	/**
	 * @param list<TimelineEntry> $entries
	 */
	private function summarise(IncidentQuery $query, array $entries, bool $truncated, IL10N $l): ReportSummary {
		$detections = array_values(array_filter($entries, static fn (TimelineEntry $e): bool => $e->kind === DetectionSource::KIND));
		$enforced = count(array_filter($detections, static fn (TimelineEntry $e): bool => $e->enforced === true));
		$counts = ['entries' => count($entries), 'detections' => count($detections), 'enforced' => $enforced, 'observed' => count($detections) - $enforced];

		$since = $this->dates->dateTime($query->since);
		$until = $this->dates->dateTime($query->until);
		$subject = $query->subject();
		if ($entries === []) {
			$headline = $query->isUser()
				? $l->t('Nextcloud recorded nothing about the account %1$s between %2$s and %3$s.', [$subject, $since, $until])
				: $l->t('Nextcloud recorded nothing about the address %1$s between %2$s and %3$s.', [$subject, $since, $until]);
		} else {
			$headline = $query->isUser()
				? $l->n('Nextcloud recorded %n event about the account %1$s between %2$s and %3$s.', 'Nextcloud recorded %n events about the account %1$s between %2$s and %3$s.', count($entries), [$subject, $since, $until])
				: $l->n('Nextcloud recorded %n event about the address %1$s between %2$s and %3$s.', 'Nextcloud recorded %n events about the address %1$s between %2$s and %3$s.', count($entries), [$subject, $since, $until]);
			if ($detections !== []) {
				$headline .= ' ' . $l->t('Detections: %1$s (acted on: %2$s, only observed: %3$s).', [(string)$counts['detections'], (string)$counts['enforced'], (string)$counts['observed']]);
			}
		}

		$categories = [];
		foreach ($entries as $entry) {
			foreach ($entry->categories as $category) {
				$categories[$category->value] = $category;
			}
		}
		$dataCategories = [];
		foreach (DataCategory::cases() as $category) {
			if (isset($categories[$category->value])) {
				$dataCategories[] = $category->label($l);
			}
		}
		$dataNote = $dataCategories === [] && $entries !== []
			? $l->t('No sign that data was opened: only failed attempts and blocks were recorded.')
			: null;

		$openItems = [];
		foreach ($entries as $entry) {
			if ($entry->followUp !== null && !in_array($entry->followUp, $openItems, true)) {
				$openItems[] = $entry->followUp;
			}
		}
		if ($truncated) {
			$openItems[] = $l->t('This report is incomplete: it holds only the first %s entries of the period. Build reports for shorter periods to see the rest.', [(string)$this->maxEntries]);
		}

		$ends = array_map(static fn (TimelineEntry $e): int => max($e->at, $e->endsAt ?? 0), $entries);
		$found = array_values(array_filter($entries, static fn (TimelineEntry $e): bool => $e->severity !== null));
		return new ReportSummary(
			$headline,
			$this->happened($entries, $l),
			$entries[0]->at ?? null,
			$found[0]->at ?? null,
			$ends === [] ? null : max($ends),
			$this->affected($query, $entries, $l),
			$dataCategories,
			$dataNote,
			$this->measures($entries, $l),
			$openItems,
			$counts,
		);
	}

	/**
	 * One line per group of entries, in the order they first happened.
	 *
	 * @param list<TimelineEntry> $entries
	 * @return list<string>
	 */
	private function happened(array $entries, IL10N $l): array {
		$groups = [];
		foreach ($entries as $entry) {
			$groups[$entry->group] ??= ['count' => 0, 'first' => $entry->at];
			$groups[$entry->group]['count']++;
		}
		$lines = [];
		foreach ($groups as $group => $info) {
			$lines[] = $l->n('%1$s: once, at %2$s', '%1$s: %n times, the first at %2$s', $info['count'], [$group, $this->dates->dateTime($info['first'])]);
		}
		return $lines;
	}

	/**
	 * @param list<TimelineEntry> $entries
	 * @return list<string>
	 */
	private function affected(IncidentQuery $query, array $entries, IL10N $l): array {
		$lines = [];
		if ($query->uid !== null) {
			$displayName = $this->userManager->get($query->uid)?->getDisplayName();
			$lines[] = $displayName !== null && $displayName !== $query->uid
				? $l->t('The account %1$s (%2$s)', [$query->uid, $displayName])
				: $l->t('The account %s', [$query->uid]);
			$addresses = array_values(array_unique(array_filter(array_map(static fn (TimelineEntry $e): ?string => $e->address, $entries))));
			if ($addresses !== []) {
				$lines[] = $l->t('Addresses involved: %s', [$this->names($addresses, $l)]);
			}
		} elseif ($query->address !== null) {
			$lines[] = $query->address->family === 6
				? $l->t('The address %1$s and its network %2$s', [$query->address->ip, $query->address->netKey])
				: $l->t('The address %s', [$query->address->ip]);
			$accounts = [];
			foreach ($entries as $entry) {
				foreach ($entry->accounts as $account) {
					$accounts[$account] = true;
				}
			}
			if ($accounts !== []) {
				$lines[] = $l->t('Accounts involved: %s', [$this->names(array_map('strval', array_keys($accounts)), $l)]);
			}
		}
		return $lines;
	}

	/**
	 * What was done, without repeating a sentence. What observed detections
	 * would have done is not a measure.
	 *
	 * @param list<TimelineEntry> $entries
	 * @return list<string>
	 */
	private function measures(array $entries, IL10N $l): array {
		$measures = [];
		foreach ($entries as $entry) {
			foreach ($entry->measures ?? ($entry->enforced === false ? [] : $entry->done) as $sentence) {
				$measures[$sentence] = true;
			}
		}
		$lines = array_map('strval', array_keys($measures));
		if (count($lines) > self::MAX_MEASURES) {
			$more = count($lines) - self::MAX_MEASURES;
			$lines = array_slice($lines, 0, self::MAX_MEASURES);
			$lines[] = $l->n('… and %n more, listed on the timeline.', '… and %n more, listed on the timeline.', $more);
		}
		return $lines;
	}

	/**
	 * @param list<string> $names
	 */
	private function names(array $names, IL10N $l): string {
		$shown = implode(', ', array_slice($names, 0, self::MAX_NAMES));
		$more = count($names) - self::MAX_NAMES;
		return $more > 0 ? $l->n('%1$s and %n more', '%1$s and %n more', $more, [$shown]) : $shown;
	}
}
