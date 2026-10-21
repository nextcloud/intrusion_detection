<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\Admin\CheckNames;
use OCA\IntrusionDetection\Admin\StatusService;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack;
use OCA\IntrusionDetection\Check\Checks\DecoyCredential;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce;
use OCA\IntrusionDetection\Db\BlocklistStatMapper;
use OCA\IntrusionDetection\Db\DigestMapper;
use OCA\IntrusionDetection\Db\ProtectedAccountMapper;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IDateTimeFormatter;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Mail\EMailDetails;
use OCP\Mail\IEMailTemplate;

/**
 * Builds the admin digest (concept section 11.10): first the numbers of a
 * period ({@see report()}), then the email in a reader's language
 * ({@see content()}). Sections without data are left out.
 *
 * The detections per check, of the period and of the one before, come
 * from the hourly totals: the period before may be older than detections
 * are kept.
 *
 * Every value is plain text; {@see Mails} escapes it for the HTML part.
 */
class Digest {
	/** Entries per list section */
	public const TOP = 10;
	/** Names of checks shown per address */
	public const CHECKS_PER_SOURCE = 3;
	/** Detections can be answered with "This was not me" this long */
	public const VERDICT_LOOKBACK = 30 * 86400;

	public function __construct(
		private readonly DetectionTotals $totals,
		private readonly DigestMapper $digests,
		private readonly ProtectedAccountMapper $protectedAccounts,
		private readonly BlocklistStatMapper $blocklistStats,
		private readonly SourceRepository $blocklistSources,
		private readonly StatusService $status,
		private readonly CheckNames $names,
		private readonly IFactory $l10nFactory,
		private readonly IDateTimeFormatter $dateFormatter,
		private readonly AdminLinks $links,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * The numbers of the period that ends at `$end`.
	 */
	public function report(DigestSchedule $schedule, int $end): DigestReport {
		[$start] = $schedule->periodEndingAt($end);
		[$previousStart] = $schedule->periodEndingAt($start);

		$status = $this->status->status($this->l10nFactory->get(Application::APP_ID, 'en'));

		$current = $this->totals->perCheckBetween($start, $end);
		$previous = $this->totals->perCheckBetween($previousStart, $start);
		$checks = [];
		foreach (array_unique(array_merge(array_keys($current), array_keys($previous))) as $checkId) {
			$checks[(string)$checkId] = [
				'enforced' => $current[$checkId]['enforced'] ?? 0,
				'observed' => $current[$checkId]['observed'] ?? 0,
				'previous' => ($previous[$checkId]['enforced'] ?? 0) + ($previous[$checkId]['observed'] ?? 0),
			];
		}
		uksort($checks, static fn (string $a, string $b): int => [$checks[$b]['enforced'] + $checks[$b]['observed'], $checks[$b]['previous'], $a]
			<=> [$checks[$a]['enforced'] + $checks[$a]['observed'], $checks[$a]['previous'], $b]);

		$sources = $this->digests->topSources($start, $end, self::TOP);
		$ips = array_column($sources, 'ip');
		$checksBySource = $this->digests->checksForSources($ips, $start, $end);
		$bansBySource = $this->digests->bansForSources($ips, $start, $end);

		return new DigestReport(
			kind: $schedule->periodKind(),
			start: $start,
			end: $end,
			previousStart: $previousStart,
			timezone: $schedule->timezone->getName(),
			state: $status['state'],
			learningDaysLeft: $status['learning']['daysLeft'],
			modes: $status['checks'],
			checks: $checks,
			enforced: array_sum(array_column($current, 'enforced')),
			observed: array_sum(array_column($current, 'observed')),
			previousDetections: array_sum(array_column($previous, 'enforced')) + array_sum(array_column($previous, 'observed')),
			bans: $this->digests->bansCreated($start, $end),
			sources: array_map(static fn (array $source): array => [
				'ip' => $source['ip'],
				'detections' => $source['detections'],
				'checks' => $checksBySource[$source['ip']] ?? [],
				'bans' => $bansBySource[$source['ip']] ?? 0,
			], $sources),
			accounts: $this->digests->accountsForCheck(AccountUnderAttack::ID, $start, $end, self::TOP),
			decoys: $this->decoys($start, $end),
			shares: $this->digests->sharesForCheck(ShareBruteforce::ID, $start, $end, self::TOP),
			blocklists: $this->blocklists($start, $end),
			protectedAccounts: array_map(static fn (array $row): array => ['uid' => $row['uid'], 'until' => $row['expires_at']],
				$this->protectedAccounts->findActive($this->timeFactory->getTime(), self::TOP)),
			deniedByUsers: $this->digests->deniedByUsers($start, $end, self::VERDICT_LOOKBACK, self::TOP),
		);
	}

	/**
	 * The digest email in one language.
	 *
	 * @param bool $test marks the email as a test, sent only to the admin who asked for it
	 */
	public function content(DigestReport $report, string $language, bool $test = false): MailContent {
		$l = $this->l10nFactory->get(Application::APP_ID, $language);
		$weekly = $report->kind === DigestSchedule::WEEKLY;
		$timezone = new \DateTimeZone($report->timezone);

		$notes = [];
		if ($test) {
			$notes[] = [
				'label' => $l->t('Test'),
				'text' => $weekly
					? $l->t('This is a test digest, sent only to you. It covers the last 7 days up to now. The real digest goes to everyone in the notification groups who has an email address.')
					: $l->t('This is a test digest, sent only to you. It covers the last 24 hours up to now. The real digest goes to everyone in the notification groups who has an email address.'),
				'type' => IEMailTemplate::NOTE_INFO,
			];
		}
		$notes[] = $this->statusNote($report, $l);
		foreach ($this->status->status($l)['problems'] as $problem) {
			$notes[] = [
				'label' => $problem['title'],
				'text' => $problem['text'],
				'type' => match ($problem['level']) {
					'error' => IEMailTemplate::NOTE_ERROR,
					'info' => IEMailTemplate::NOTE_INFO,
					default => IEMailTemplate::NOTE_WARNING,
				},
			];
		}

		$paragraphs = [$l->t('From %1$s to %2$s (%3$s).', [
			$this->dateFormatter->formatDateTime($report->start, 'full', 'short', $timezone, $l),
			$this->dateFormatter->formatDateTime($report->end, 'full', 'short', $timezone, $l),
			$report->timezone,
		])];

		if ($report->isQuiet()) {
			$paragraphs[] = $l->t('Nothing happened: no detections, no blocks and no blocklist matches. Intrusion detection is running and watching.');
			$subject = $weekly ? $l->t('Intrusion detection weekly summary: nothing happened') : $l->t('Intrusion detection daily summary: nothing happened');
			$details = [];
		} else {
			$paragraphs[] = $this->summary($report, $l);
			$subject = $weekly
				? $l->n('Intrusion detection weekly summary: %n detection', 'Intrusion detection weekly summary: %n detections', $report->detections())
				: $l->n('Intrusion detection daily summary: %n detection', 'Intrusion detection daily summary: %n detections', $report->detections());
			$details = array_values(array_filter([
				$this->checksCard($report, $l),
				$this->sourcesCard($report, $l),
				$this->accountsCard($report, $l),
				$this->decoysCard($report, $l, $timezone),
				$this->sharesCard($report, $l),
				$this->blocklistsCard($report, $l),
				$this->openItemsCard($report, $l, $timezone),
			]));
		}

		return new MailContent(
			templateId: 'intrusion_detection.digest',
			subject: $test ? $l->t('Test: %s', [$subject]) : $subject,
			heading: $weekly ? $l->t('Weekly security summary') : $l->t('Daily security summary'),
			paragraphs: $paragraphs,
			buttonText: $l->t('Open intrusion detection'),
			buttonUrl: $this->links->adminPage(),
			language: $language,
			notes: $notes,
			details: $details,
			notesAfterParagraphs: true,
		);
	}

	/**
	 * @return array{text: string, label: string, type: IEMailTemplate::NOTE_*}
	 */
	private function statusNote(DigestReport $report, IL10N $l): array {
		return match ($report->state) {
			'learning' => [
				// A single word and a colon would be read as a plural label by n(), so it is outside it.
				'label' => $l->t('Learning: %s', [$l->n('%n day left', '%n days left', $report->learningDaysLeft)]),
				'text' => $l->t('Nextcloud is watching, not acting. Checks set to Protect only record what they would have done.'),
				'type' => IEMailTemplate::NOTE_INFO,
			],
			'off' => [
				'label' => $l->t('Off'),
				'text' => $l->t('No checks run and blocks are not enforced. You can turn intrusion detection on again on the admin page.'),
				'type' => IEMailTemplate::NOTE_WARNING,
			],
			default => [
				'label' => $l->t('Protecting'),
				'text' => $l->t('Checks: %1$s protecting, %2$s observing, %3$s off.', [
					(string)$report->modes['protect'],
					(string)$report->modes['observe'],
					(string)$report->modes['off'],
				]),
				'type' => IEMailTemplate::NOTE_INFO,
			],
		};
	}

	private function summary(DigestReport $report, IL10N $l): string {
		$sentences = [
			$l->n('%n detection in this period.', '%n detections in this period.', $report->detections()),
			$l->t('Nextcloud acted on %1$s and observed %2$s.', [(string)$report->enforced, (string)$report->observed]),
			$report->kind === DigestSchedule::WEEKLY
				? $l->n('The week before: %n detection.', 'The week before: %n detections.', $report->previousDetections)
				: $l->n('The day before: %n detection.', 'The day before: %n detections.', $report->previousDetections),
			$l->n('%n address or network was blocked.', '%n addresses or networks were blocked.', $report->bans),
		];
		return implode(' ', $sentences);
	}

	private function checksCard(DigestReport $report, IL10N $l): ?EMailDetails {
		if ($report->checks === []) {
			return null;
		}
		$card = new EMailDetails($l->t('Detections per check'));
		$card->setSubtitle($report->kind === DigestSchedule::WEEKLY ? $l->t('This week, and the week before') : $l->t('Today, and the day before'));
		foreach ($report->checks as $checkId => $counts) {
			$row = $card->addRow($this->names->name($checkId, $l))
				->text($l->t('%1$s (before: %2$s)', [(string)($counts['enforced'] + $counts['observed']), (string)$counts['previous']]));
			if ($counts['enforced'] + $counts['observed'] > 0) {
				$row->muted($l->t('%1$s acted on, %2$s observed', [(string)$counts['enforced'], (string)$counts['observed']]));
			}
		}
		return $card;
	}

	private function sourcesCard(DigestReport $report, IL10N $l): ?EMailDetails {
		if ($report->sources === []) {
			return null;
		}
		$card = new EMailDetails($l->t('Most active addresses'));
		foreach ($report->sources as $source) {
			$checks = array_map(fn (string $id): string => $this->names->name($id, $l), array_slice($source['checks'], 0, self::CHECKS_PER_SOURCE));
			$card->addRow($source['ip'])
				->text(implode(', ', $checks))
				->muted($l->n('%n detection', '%n detections', $source['detections']) . ' · ' . $l->n('%n block', '%n blocks', $source['bans']));
		}
		return $card;
	}

	private function accountsCard(DigestReport $report, IL10N $l): ?EMailDetails {
		if ($report->accounts === []) {
			return null;
		}
		$card = new EMailDetails($l->t('Accounts under attack'));
		$card->setSubtitle($l->t('Passwords guessed from many different addresses'));
		foreach ($report->accounts as $account) {
			$card->addRow($account['uid'])->text($l->n('%n detection', '%n detections', $account['detections']));
		}
		return $card;
	}

	private function decoysCard(DigestReport $report, IL10N $l, \DateTimeZone $timezone): ?EMailDetails {
		if ($report->decoys === []) {
			return null;
		}
		$card = new EMailDetails($l->t('Decoys that were used'));
		$card->setSubtitle($l->t('Someone found a planted credential and tried it'));
		foreach ($report->decoys as $decoy) {
			$card->addRow($decoy['label'])
				->text($l->n('Used from %n address', 'Used from %n addresses', $decoy['addresses']))
				->muted($l->t('Last used: %s', [$this->dateFormatter->formatDateTime($decoy['lastAt'], 'long', 'short', $timezone, $l)]));
		}
		return $card;
	}

	private function sharesCard(DigestReport $report, IL10N $l): ?EMailDetails {
		if ($report->shares === []) {
			return null;
		}
		$card = new EMailDetails($l->t('Shares under attack'));
		$card->setSubtitle($l->t('Share link passwords being guessed'));
		foreach ($report->shares as $share) {
			$row = $card->addRow($l->t('Share %s', [(string)$share['shareId']]));
			if ($share['owner'] !== null) {
				$row->text($l->t('Shared by %s', [$share['owner']]));
			}
			$row->muted($l->n('%n detection', '%n detections', $share['detections']));
		}
		return $card;
	}

	private function blocklistsCard(DigestReport $report, IL10N $l): ?EMailDetails {
		if ($report->blocklistMatches() === 0) {
			return null;
		}
		$card = new EMailDetails($l->t('Blocklist matches'));
		$card->setSubtitle($l->t('Requests from addresses on a list you enabled'));
		foreach ($report->blocklists as $list) {
			if ($list['matches'] > 0) {
				$card->addRow($list['name'])->text($l->n('%n match', '%n matches', $list['matches']));
			}
		}
		return $card;
	}

	private function openItemsCard(DigestReport $report, IL10N $l, \DateTimeZone $timezone): ?EMailDetails {
		if ($report->protectedAccounts === [] && $report->deniedByUsers === []) {
			return null;
		}
		$card = new EMailDetails($l->t('Open items'));
		if ($report->protectedAccounts !== []) {
			$row = $card->addRow($l->t('Accounts that need extra confirmation'));
			foreach ($report->protectedAccounts as $account) {
				$row->text($l->t('%1$s, until %2$s', [$account['uid'], $this->dateFormatter->formatDateTime($account['until'], 'long', 'short', $timezone, $l)]));
			}
		}
		if ($report->deniedByUsers !== []) {
			$row = $card->addRow($l->t('Answered "This was not me"'));
			foreach ($report->deniedByUsers as $denied) {
				$row->text($l->t('%1$s: %2$s', [$denied['uid'], $this->names->name($denied['checkId'], $l)]));
			}
		}
		return $card;
	}

	/**
	 * @return list<array{label: string, detections: int, addresses: int, lastAt: int}>
	 */
	private function decoys(int $start, int $end): array {
		$decoys = [];
		foreach ($this->digests->detectionsOfCheck(DecoyCredential::ID, $start, $end) as $detection) {
			$facts = $detection->getExplanationData()['facts'] ?? [];
			$facts = is_array($facts) ? $facts : [];
			$key = (string)($facts['decoy'] ?? '');
			$decoys[$key] ??= ['label' => (string)($facts['label'] ?? ''), 'detections' => 0, 'ips' => [], 'lastAt' => 0];
			$decoys[$key]['detections']++;
			if ($detection->getIp() !== null) {
				$decoys[$key]['ips'][$detection->getIp()] = true;
			}
			$decoys[$key]['lastAt'] = max($decoys[$key]['lastAt'], $detection->getLastSeenAt());
		}
		usort($decoys, static fn (array $a, array $b): int => [$b['detections'], $b['lastAt']] <=> [$a['detections'], $a['lastAt']]);
		return array_map(static fn (array $decoy): array => [
			'label' => $decoy['label'],
			'detections' => $decoy['detections'],
			'addresses' => count($decoy['ips']),
			'lastAt' => $decoy['lastAt'],
		], array_slice($decoys, 0, self::TOP));
	}

	/**
	 * Matches per list in the period. They are counted per UTC day, and a
	 * day belongs to the period its midnight falls in, so consecutive
	 * digests never count a day twice.
	 *
	 * @return list<array{id: string, name: string, matches: int}>
	 */
	private function blocklists(int $start, int $end): array {
		$names = [];
		foreach ($this->blocklistSources->all() as $source) {
			$names[$source->id] = $source->name;
		}
		$firstDay = gmdate('Y-m-d', $start + (86400 - $start % 86400) % 86400);
		$lastDay = gmdate('Y-m-d', $end - 1);
		$matches = [];
		foreach ($this->blocklistStats->findSince(array_keys($names), $firstDay) as $row) {
			if ($row['day'] <= $lastDay) {
				$matches[$row['listId']] = ($matches[$row['listId']] ?? 0) + $row['matches'];
			}
		}
		arsort($matches);
		$lists = [];
		foreach (array_slice($matches, 0, self::TOP, true) as $id => $count) {
			$lists[] = ['id' => (string)$id, 'name' => $names[$id] ?? (string)$id, 'matches' => $count];
		}
		return $lists;
	}
}
