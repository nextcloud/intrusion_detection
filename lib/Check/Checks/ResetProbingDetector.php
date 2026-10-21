<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Risk\RiskScorer;

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
 * FLOOD_SAMPLE; only a kept one is evaluated, and the counts are scaled by
 * the sample factor. Fewer than MIN_RAW recorded rows never fire.
 */
class ResetProbingDetector {
	public const MIN_RAW = 3;
	/** At most this many existing accounts are listed for an enumeration */
	public const MAX_TARGETS = 20;

	public function __construct(
		private readonly Settings $settings,
		private readonly AttemptMapper $attempts,
		private readonly AttemptRecorder $recorder,
		private readonly ResponseEngine $engine,
		private readonly DetectionService $detections,
		private readonly ResetProbing $check,
		private readonly RiskScorer $risk,
	) {
	}

	public function detect(#[\SensitiveParameter] AttemptRecord $attempt, ?string $userAgent): void {
		if ($attempt->kind !== AttemptKind::PasswordReset || !$attempt->stored) {
			return;
		}
		if (!$this->settings->modeState(ResetProbing::ID)->runs()) {
			return;
		}
		$params = $this->settings->params(ResetProbing::ID);
		$factor = $this->recorder->sampleFactor(AttemptKind::PasswordReset, $attempt->time);
		$kinds = [AttemptKind::PasswordReset];

		$since = $attempt->time - (int)$params['enum_window'];
		$ip = $this->attempts->stats('ip_key', [$attempt->source->ipKey], $kinds, $since);
		$enumLimits = $this->risk->limits($attempt->source, ['enum_min_inputs' => [(int)$params['enum_min_inputs'], $ip->distinctNames * $factor]]);
		if (self::reaches($ip->distinctNames, $factor, $enumLimits->of('enum_min_inputs'))) {
			$this->handle(new DetectionDraft(
				checkId: ResetProbing::ID,
				source: $attempt->source,
				facts: [
					'rule' => ResetProbing::RULE_ENUMERATION,
					'inputs' => $ip->distinctNames * $factor,
					'requests' => $ip->failures * $factor,
					'sampleFactor' => $factor,
					'targets' => $this->attempts->distinctUids('ip_key', [$attempt->source->ipKey], $kinds, $since, self::MAX_TARGETS),
					'first' => $ip->first,
					'last' => $ip->last,
				] + $enumLimits->facts(),
				merge: DetectionDraft::MERGE_SOURCE,
				userAgent: $userAgent,
			), $params);
		}

		$uid = $attempt->uid;
		if ($uid === null) {
			return;
		}
		$user = $this->attempts->stats('uid', [$uid], $kinds, $attempt->time - (int)$params['flood_window']);
		$floodLimits = $this->risk->limits($attempt->source, ['flood_min_requests' => [(int)$params['flood_min_requests'], $user->failures * $factor]]);
		if (self::reaches($user->failures, $factor, $floodLimits->of('flood_min_requests'))) {
			$this->handle(new DetectionDraft(
				checkId: ResetProbing::ID,
				uid: $uid,
				facts: [
					'rule' => ResetProbing::RULE_FLOOD,
					'requests' => $user->failures * $factor,
					'sources' => $user->distinctSources,
					'sampleFactor' => $factor,
					'lastSource' => $attempt->source->ip,
					'first' => $user->first,
					'last' => $user->last,
				] + $floodLimits->facts(),
				merge: DetectionDraft::MERGE_USER,
				mergeWindow: max((int)$params['flood_window'], (int)$params['suppress_duration']),
				userAgent: $userAgent,
			), $params);
		}
	}

	/**
	 * @param array<string, int|float|bool|string|list<string>> $params
	 */
	private function handle(DetectionDraft $draft, array $params): void {
		$responses = $this->check->responsesFor($draft, $this->settings->responses(ResetProbing::ID), $params);
		if ($draft->uid !== null && $this->continuesDetection($draft)) {
			// The person was told when this flood began.
			$responses = array_values(array_filter($responses, static fn (ResponseType $r): bool => $r !== ResponseType::NotifyUser));
		}
		$this->engine->handle($draft, $responses);
	}

	/**
	 * Whether the draft will be merged into an earlier detection.
	 */
	private function continuesDetection(DetectionDraft $draft): bool {
		return $this->detections->mergeTarget($draft, $this->settings->modeState(ResetProbing::ID)) !== null;
	}

	private static function reaches(int $raw, int $factor, int $threshold): bool {
		return $raw >= self::MIN_RAW && $raw * $factor >= $threshold;
	}
}
