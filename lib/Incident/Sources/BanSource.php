<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident\Sources;

use OCA\IntrusionDetection\Admin\CheckNames;
use OCA\IntrusionDetection\Check\Checks\ManualBlock\ManualBlock;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\ITimelineSource;
use OCA\IntrusionDetection\Incident\TimelineEntry;
use OCP\IL10N;

/**
 * Blocks in force during the period: for an address, the blocks of the
 * address and of its network; for an account, the blocks its detections
 * caused. A block lifted within the period adds a second entry.
 */
class BanSource implements ITimelineSource {
	public const KIND = 'block';
	public const KIND_LIFTED = 'block_lifted';

	public function __construct(
		private readonly BanMapper $bans,
		private readonly CheckNames $names,
		private readonly DateFormatter $dates,
	) {
	}

	#[\Override]
	public function kinds(IL10N $l): array {
		return [
			self::KIND => $l->t('Blocks'),
			self::KIND_LIFTED => $l->t('Blocks lifted'),
		];
	}

	#[\Override]
	public function entriesFor(IncidentQuery $query, IL10N $l): iterable {
		$keys = $query->address === null ? [] : array_values(array_unique([$query->address->ipKey, $query->address->netKey]));
		$entries = [];
		foreach ($this->bans->findForIncident($keys, $query->uid, false, $query->since, $query->until, $query->limit) as $ban) {
			$entries[] = $this->created($ban, $l);
		}
		foreach ($this->bans->findForIncident($keys, $query->uid, true, $query->since, $query->until, $query->limit) as $ban) {
			$entries[] = $this->lifted($ban, (int)$ban->getLiftedAt(), $l);
		}
		usort($entries, static fn (TimelineEntry $a, TimelineEntry $b): int => $a->at <=> $b->at);
		return array_slice($entries, 0, $query->limit);
	}

	private function created(Ban $ban, IL10N $l): TimelineEntry {
		$cidr = $ban->getCidr();
		$details = [
			$l->t('Block level %1$s of 3, reference %2$s.', [(string)$ban->getLevel(), $ban->getDisplayReference()]),
			$ban->getCheckId() === ManualBlock::ID
				? $l->t('Added by hand by %s.', [(string)($ban->getCreatedBy() ?? '?')])
				: $l->t('Caused by the check "%s".', [$this->names->name($ban->getCheckId(), $l)]),
		];
		if (($ban->getNote() ?? '') !== '') {
			$details[] = $l->t('Note: %s', [(string)$ban->getNote()]);
		}
		$details[] = $ban->getLiftedAt() === null
			? $l->t('Blocked until %s.', [$this->dates->dateTime($ban->getExpiresAt())])
			: $l->t('Planned until %s, lifted earlier.', [$this->dates->dateTime($ban->getExpiresAt())]);
		return new TimelineEntry(
			id: 'block:' . (string)$ban->getId(),
			at: $ban->getCreatedTime(),
			kind: self::KIND,
			group: $l->t('Blocks'),
			title: $ban->getScope() === Ban::SCOPE_NET ? $l->t('Network %s blocked', [$cidr]) : $l->t('Address %s blocked', [$cidr]),
			endsAt: $ban->getLiftedAt() ?? $ban->getExpiresAt(),
			details: $details,
			// Automatic blocks are part of what their detection did; only blocks added by hand are a measure of their own.
			done: $ban->getCheckId() === ManualBlock::ID ? [$l->t('%1$s was blocked by hand until %2$s.', [$cidr, $this->dates->dateTime($ban->getLiftedAt() ?? $ban->getExpiresAt())])] : [],
			address: $cidr,
			ref: ['type' => 'block', 'id' => $ban->getDisplayReference()],
		);
	}

	private function lifted(Ban $ban, int $liftedAt, IL10N $l): TimelineEntry {
		$details = [$l->t('Lifted by %s.', [(string)($ban->getLiftedBy() ?? '?')])];
		if (($ban->getLiftNote() ?? '') !== '') {
			$details[] = $l->t('Note: %s', [(string)$ban->getLiftNote()]);
		}
		return new TimelineEntry(
			id: 'block-lifted:' . (string)$ban->getId(),
			at: $liftedAt,
			kind: self::KIND_LIFTED,
			group: $l->t('Blocks lifted'),
			title: $l->t('Block of %s lifted', [$ban->getCidr()]),
			details: $details,
			address: $ban->getCidr(),
			ref: ['type' => 'block', 'id' => $ban->getDisplayReference()],
		);
	}
}
