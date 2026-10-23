<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\ResetProbing;

use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;
use OCA\IntrusionDetection\Signal\ResetRequested;

/**
 * Detects password reset abuse (concept section 10.10) after each reset request.
 *
 * 1. Enumeration: one address asked for resets for at least
 *    `enum_min_inputs` different inputs within `enum_window`.
 * 2. Flooding: one account was asked for at least `flood_min_requests`
 *    reset emails within `flood_window`, from any addresses. A whole flood
 *    is one detection, and the person is told once.
 *
 * Both limits are lowered when the requesting address has an elevated or
 * high risk score ({@see RiskScorer::limits()}).
 *
 * Under a flood of attempts the recorder keeps one reset request in
 * FLOOD_SAMPLE; only a kept one is evaluated, and each kept row counts with
 * its stored weight, so rows from before the flood count once. Fewer than
 * MIN_RAW recorded rows never fire.
 *
 * @template-implements IDetector<ResetRequested>
 */
class ResetProbingDetector implements IDetector {
	public const MIN_RAW = 3;
	/** At most this many existing accounts are listed for an enumeration */
	public const MAX_TARGETS = 20;

	public function __construct(
		private readonly CheckSettings $settings,
		private readonly AttemptMapper $attempts,
		private readonly RiskScorer $risk,
	) {
	}

	/**
	 * @param ResetRequested $signal
	 * @return list<DetectionDraft>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): iterable {
		$attempt = $signal->attempt;
		$userAgent = $signal->userAgent;
		if ($attempt->kind !== AttemptKind::PasswordReset || !$attempt->stored) {
			return [];
		}
		$drafts = [];
		$params = $this->settings->params(ResetProbing::ID);
		$kinds = [AttemptKind::PasswordReset];

		$since = $attempt->time - (int)$params['enum_window'];
		$ip = $this->attempts->stats('ip_key', [$attempt->source->ipKey], $kinds, $since);
		$enumLimits = $this->risk->limits($attempt->source, ['enum_min_inputs' => [(int)$params['enum_min_inputs'], $ip->namesEstimate()]]);
		if (self::reaches($ip->distinctNames, $ip->namesEstimate(), $enumLimits->of('enum_min_inputs'))) {
			$drafts[] = new DetectionDraft(
				checkId: ResetProbing::ID,
				source: $attempt->source,
				facts: [
					'rule' => ResetProbing::RULE_ENUMERATION,
					'inputs' => $ip->namesEstimate(),
					'requests' => $ip->failuresEstimate(),
					'sampleFactor' => $ip->maxWeight,
					'targets' => $this->attempts->distinctUids('ip_key', [$attempt->source->ipKey], $kinds, $since, self::MAX_TARGETS),
					'first' => $ip->first,
					'last' => $ip->last,
				] + $enumLimits->facts(),
				merge: DetectionDraft::MERGE_SOURCE,
				userAgent: $userAgent,
			);
		}

		$uid = $attempt->uid;
		if ($uid === null) {
			return $drafts;
		}
		$user = $this->attempts->stats('uid', [$uid], $kinds, $attempt->time - (int)$params['flood_window']);
		$floodLimits = $this->risk->limits($attempt->source, ['flood_min_requests' => [(int)$params['flood_min_requests'], $user->failuresEstimate()]]);
		if (self::reaches($user->failures, $user->failuresEstimate(), $floodLimits->of('flood_min_requests'))) {
			$draft = new DetectionDraft(
				checkId: ResetProbing::ID,
				uid: $uid,
				facts: [
					'rule' => ResetProbing::RULE_FLOOD,
					'requests' => $user->failuresEstimate(),
					'sources' => $user->distinctSources,
					'sampleFactor' => $user->maxWeight,
					'lastSource' => $attempt->source->ip,
					'first' => $user->first,
					'last' => $user->last,
				] + $floodLimits->facts(),
				merge: DetectionDraft::MERGE_USER,
				mergeWindow: max((int)$params['flood_window'], (int)$params['suppress_duration']),
				userAgent: $userAgent,
			);
			// The person is told when the flood begins, not for every request that continues it.
			$draft->runOnlyWhenNew(ResponseType::NotifyUser);
			$drafts[] = $draft;
		}
		return $drafts;
	}

	/**
	 * Whether a count reaches a threshold: the estimate, and at least
	 * MIN_RAW stored rows.
	 */
	private static function reaches(int $raw, int $estimate, int $threshold): bool {
		return $raw >= self::MIN_RAW && $estimate >= $threshold;
	}
}
