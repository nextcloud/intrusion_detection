<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident\Sources;

use OCA\IntrusionDetection\Admin\DetectionPresenter;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChangeFacts;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Incident\DataCategory;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\ITimelineSource;
use OCA\IntrusionDetection\Incident\MatchingRows;
use OCA\IntrusionDetection\Incident\Measures;
use OCA\IntrusionDetection\Incident\TimelineEntry;
use OCP\IL10N;

/**
 * Administration changes made by the account, or from the address, and
 * the decisions on requests for approval that concern the account.
 *
 * Changes made to the account (it was made an administrator, for example)
 * are detections about it and come from {@see DetectionSource}; this
 * source adds what the account did to others, which matters when an
 * administrator account was taken over.
 */
class AdminChangeSource implements ITimelineSource {
	public const KIND = 'admin_change';
	public const KIND_APPROVAL = 'approval';

	public function __construct(
		private readonly DetectionMapper $detections,
		private readonly ApprovalMapper $approvals,
		private readonly NarrativeBuilder $narratives,
		private readonly AdminChange $check,
		private readonly DateFormatter $dates,
		private readonly Measures $measures,
	) {
	}

	#[\Override]
	public function kinds(IL10N $l): array {
		return [
			self::KIND => $l->t('Administration changes'),
			self::KIND_APPROVAL => $l->t('Approvals'),
		];
	}

	#[\Override]
	public function entriesFor(IncidentQuery $query, IL10N $l): iterable {
		$entries = [];
		foreach ($this->changes($query) as $detection) {
			$entries[] = $this->change($detection, $query, $l);
		}
		foreach ([false, true] as $decided) {
			foreach ($this->approvals->findForIncident($query->uid, $query->address?->ip, $decided, $query->since, $query->until, $query->limit) as $approval) {
				$entries[] = $this->approval($approval, $decided, $l);
			}
		}
		usort($entries, static fn (TimelineEntry $a, TimelineEntry $b): int => $a->at <=> $b->at);
		return array_slice($entries, 0, $query->limit);
	}

	/**
	 * @return list<Detection>
	 */
	private function changes(IncidentQuery $query): array {
		[$field, $value] = $query->uid !== null ? ['actor', $query->uid] : ['actor_ip', (string)$query->address?->ip];
		// The actor is recorded as an account of the detection; an address is only in its facts.
		$needle = $query->uid !== null ? null : '"' . $field . '":' . json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
		return MatchingRows::collect(
			fn (?Detection $after, int $limit): array => $this->detections->findOfCheckFor(AdminChange::ID, $query->uid, $needle, $query->since, $query->until, $limit, $after),
			// Changes to the account itself are its own detections already.
			static fn (Detection $d): bool => self::actorOf($d, $query->uid !== null) === $value && ($query->uid === null || $d->getUid() !== $query->uid),
			$query->limit,
		);
	}

	/**
	 * The account that made a change, or the address it came from.
	 */
	private static function actorOf(Detection $detection, bool $account): string {
		$facts = AdminChangeFacts::fromArray(DetectionFacts::of($detection)->facts);
		return ($account ? $facts->actor : $facts->actorIp) ?? '';
	}

	private function change(Detection $detection, IncidentQuery $query, IL10N $l): TimelineEntry {
		$narrative = $this->narratives->build($detection, $l);
		$facts = AdminChangeFacts::fromArray(DetectionFacts::of($detection)->facts);
		return new TimelineEntry(
			id: 'detection:' . (int)$detection->getId(),
			at: $detection->getCreatedAt(),
			kind: self::KIND,
			group: $query->isUser() ? $l->t('Administration changes made by the account') : $l->t('Administration changes made from the address'),
			title: $this->check->headline($detection, $l) ?? $narrative->title,
			severity: $detection->getSeverity(),
			enforced: $detection->isEnforced(),
			details: $narrative->happened,
			done: $narrative->done,
			note: $narrative->observedBecause,
			address: ($facts->actorIp ?? '') !== '' ? $facts->actorIp : null,
			accounts: array_values(array_filter([$detection->getUid(), $facts->actor], static fn (?string $a): bool => $a !== null && $a !== '')),
			ref: ['type' => 'detection', 'id' => (string)$detection->getId()],
			categories: [DataCategory::Administration],
			followUp: $l->t('Review every administration change listed here and undo the ones that were not planned.'),
			measures: $this->measures->of($detection, $l),
			outcome: DetectionPresenter::outcome($detection),
		);
	}

	private function approval(Approval $approval, bool $decided, IL10N $l): TimelineEntry {
		$subject = $approval->getSubjectUid();
		$what = match ($approval->getKind()) {
			Approval::KIND_ADMIN_GRANT => $l->t('%s to become an administrator', [$subject]),
			Approval::KIND_SETTINGS => $l->t('a settings change that switches off the approval of new administrators'),
			default => $l->t('a request about %s', [$subject]),
		};
		$details = [$l->t('Requested by %1$s at %2$s.', [AdminChange::actorName($approval->getRequestedBy(), $l), $this->dates->dateTime($approval->getCreatedAt())])];
		if (!$decided) {
			$details[] = $l->t('It waits for a decision until %s.', [$this->dates->dateTime($approval->getExpiresAt())]);
			return $this->approvalEntry($approval, $approval->getCreatedAt(), $l->t('Request waiting for approval: %s', [$what]), $details, $l, $l->t('A request for approval is still waiting. Decide it on the Overview tab or with occ intrusion:approvals:decide, or let it expire.'));
		}
		$decider = AdminChange::actorName((string)$approval->getDecidedBy(), $l);
		$title = match ($approval->getStatus()) {
			Approval::STATUS_APPROVED => $l->t('Approved by %1$s: %2$s', [$decider, $what]),
			Approval::STATUS_REJECTED => $l->t('Rejected by %1$s: %2$s', [$decider, $what]),
			default => $l->t('Request expired without a decision: %s', [$what]),
		};
		return $this->approvalEntry($approval, (int)$approval->getDecidedAt(), $title, $details, $l, null);
	}

	/**
	 * @param list<string> $details
	 */
	private function approvalEntry(Approval $approval, int $at, string $title, array $details, IL10N $l, ?string $followUp): TimelineEntry {
		return new TimelineEntry(
			id: 'approval:' . (int)$approval->getId() . ':' . $approval->getStatus(),
			at: $at,
			kind: self::KIND_APPROVAL,
			group: $l->t('Approvals'),
			title: $title,
			details: $details,
			address: $approval->getIp(),
			accounts: [$approval->getSubjectUid()],
			ref: ['type' => 'approval', 'id' => (string)$approval->getId()],
			categories: [DataCategory::Administration],
			followUp: $followUp,
		);
	}
}
