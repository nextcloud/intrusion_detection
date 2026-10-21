<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident\Sources;

use OCA\IntrusionDetection\Admin\CheckNames;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\DetectionHeadline;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Incident\DataCategory;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\ITimelineSource;
use OCA\IntrusionDetection\Incident\MatchingRows;
use OCA\IntrusionDetection\Incident\Measures;
use OCA\IntrusionDetection\Incident\TimelineEntry;
use OCP\IL10N;

/**
 * The detections of the account or the address, each with its narrative:
 * what happened, and what Nextcloud did about it (or would have done).
 *
 * For an account: its own detections and those that targeted it. For an
 * address: the detections of that address (IPv4), or of its /64 (IPv6),
 * whoever they concerned.
 */
class DetectionSource implements ITimelineSource {
	public const KIND = 'detection';

	public function __construct(
		private readonly DetectionMapper $detections,
		private readonly NarrativeBuilder $narratives,
		private readonly CheckNames $names,
		private readonly DetectionHeadline $headlines,
		private readonly Measures $measures,
	) {
	}

	#[\Override]
	public function kinds(IL10N $l): array {
		return [self::KIND => $l->t('Detections')];
	}

	#[\Override]
	public function entriesFor(IncidentQuery $query, IL10N $l): iterable {
		$address = $query->address;
		$uid = $query->uid;
		// An account's report also has the attacks that targeted it, e.g. a credential stuffing run.
		$rows = MatchingRows::collect(
			fn (?Detection $after, int $limit): array => $this->detections->findForIncident(
				$uid,
				$uid === null && $address !== null && $address->family === 4 ? $address->ip : null,
				$uid === null && $address !== null && $address->family === 6 ? $address->netKey : null,
				$query->since,
				$query->until,
				$limit,
				$after,
			),
			static fn (Detection $d): bool => $uid === null || $d->getUid() === $uid || in_array($uid, DetectionFacts::of($d)->list('targets'), true),
			$query->limit,
		);
		foreach ($rows as $detection) {
			yield $this->entry($detection, $l);
		}
	}

	private function entry(Detection $detection, IL10N $l): TimelineEntry {
		$checkId = $detection->getCheckId();
		$narrative = $this->narratives->build($detection, $l);
		$group = $this->names->name($checkId, $l);
		$enforced = $detection->isEnforced();
		$uid = $detection->getUid();
		$accounts = $uid !== null ? [$uid] : [];
		foreach (DetectionFacts::of($detection)->list('targets') as $target) {
			if (!in_array($target, $accounts, true)) {
				$accounts[] = $target;
			}
		}
		$details = $narrative->happened;
		$userAgent = $detection->getExplanationData()['userAgent'] ?? null;
		if (is_string($userAgent) && $userAgent !== '') {
			$details[] = $l->t('Client: %s', [$userAgent]);
		}
		$followUp = $enforced ? null : $l->t('Some detections were only observed, so Nextcloud did nothing about them. Decide whether they need action, for example blocking an address or asking the account owner to change their password.');
		return new TimelineEntry(
			id: 'detection:' . (int)$detection->getId(),
			at: $detection->getCreatedAt(),
			kind: self::KIND,
			group: $group,
			title: $this->headlines->custom($detection, $l) ?? $group,
			endsAt: $detection->getLastSeenAt() > $detection->getCreatedAt() ? $detection->getLastSeenAt() : null,
			severity: $detection->getSeverity(),
			enforced: $enforced,
			details: $details,
			done: $narrative->done,
			note: $narrative->observedBecause,
			address: $detection->getIp(),
			accounts: $accounts,
			ref: ['type' => 'detection', 'id' => (string)$detection->getId()],
			categories: DataCategory::forCheck($checkId),
			followUp: $followUp,
			measures: $this->measures->of($detection, $l),
		);
	}
}
