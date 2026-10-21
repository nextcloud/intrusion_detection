<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident\Sources;

use OCA\IntrusionDetection\Db\Lockdown;
use OCA\IntrusionDetection\Db\LockdownMapper;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\ITimelineSource;
use OCA\IntrusionDetection\Incident\TimelineEntry;
use OCA\IntrusionDetection\Lockdown\LockdownEffect;
use OCP\IL10N;

/**
 * Lockdowns that were on during the period. A lockdown concerns every
 * account and address, so it belongs to every report: it explains why
 * logins needed confirmation and new devices were refused at the time.
 */
class LockdownSource implements ITimelineSource {
	public const KIND = 'lockdown';

	public function __construct(
		private readonly LockdownMapper $lockdowns,
		private readonly DateFormatter $dates,
	) {
	}

	#[\Override]
	public function kinds(IL10N $l): array {
		return [self::KIND => $l->t('Lockdowns')];
	}

	#[\Override]
	public function entriesFor(IncidentQuery $query, IL10N $l): iterable {
		foreach ($this->lockdowns->overlapping($query->since, $query->until, $query->limit) as $lockdown) {
			yield $this->entry($lockdown, $l);
		}
	}

	private function entry(Lockdown $lockdown, IL10N $l): TimelineEntry {
		$startedBy = $lockdown->getStartedBy();
		$details = [match ($startedBy) {
			Lockdown::ACTOR_AUTOMATIC => $l->t('Started automatically because many addresses tried passwords at the same time.'),
			Lockdown::ACTOR_OCC => $l->t('Started with a command on the server.'),
			default => $l->t('Started by %s.', [$startedBy]),
		}];
		if (($lockdown->getReason() ?? '') !== '') {
			$details[] = $l->t('Reason: "%s"', [(string)$lockdown->getReason()]);
		}
		$effects = array_filter(array_map(
			static fn (string $id): ?string => LockdownEffect::tryFrom($id)?->label($l),
			$lockdown->getEffectList(),
		));
		if ($effects !== []) {
			$details[] = $l->t('Effects: %s.', [implode('; ', $effects)]);
		}
		$endedBy = $lockdown->getEndedBy();
		$details[] = match (true) {
			$lockdown->getEndedAt() === null => $l->t('Planned until %s.', [$this->dates->dateTime($lockdown->getPlannedEnd())]),
			$endedBy === Lockdown::ACTOR_AUTOMATIC => $l->t('Ended at its planned time, %s.', [$this->dates->dateTime($lockdown->endsAt())]),
			$endedBy === Lockdown::ACTOR_OCC => $l->t('Ended at %s with a command on the server.', [$this->dates->dateTime($lockdown->endsAt())]),
			default => $l->t('Ended at %1$s by %2$s.', [$this->dates->dateTime($lockdown->endsAt()), (string)$endedBy]),
		};
		return new TimelineEntry(
			id: 'lockdown:' . (int)$lockdown->getId(),
			at: $lockdown->getStartedAt(),
			kind: self::KIND,
			group: $l->t('Lockdowns'),
			title: $l->t('Lockdown until %s', [$this->dates->dateTime($lockdown->endsAt())]),
			endsAt: $lockdown->endsAt(),
			details: $details,
			done: [$l->t('Lockdown mode was on from %1$s to %2$s.', [$this->dates->dateTime($lockdown->getStartedAt()), $this->dates->dateTime($lockdown->endsAt())])],
			ref: ['type' => 'lockdown', 'id' => (string)$lockdown->getId()],
		);
	}
}
