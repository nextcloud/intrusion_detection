<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\AccountUnderAttack;

use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\Signal\FailedLoginAttempt;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;

/**
 * Detects one account attacked from many places (concept section 10.3)
 * after each failed login whose login name belongs to an account.
 *
 * The detection is about the account, so it has no single source address.
 * The limits are lowered when the address of the failed login has an
 * elevated or high risk score ({@see RiskScorer::limits()}).
 * The protection lasts `protect_duration` from the last time the limits
 * were reached: single failures below them never extend it, so nobody can
 * keep an account protected with an occasional guess.
 *
 * @template-implements IDetector<FailedLoginAttempt>
 */
class AccountUnderAttackDetector implements IDetector {
	public const KINDS = [AttemptKind::PasswordLogin, AttemptKind::AppPassword];
	/** Blocking blocks at most this many addresses per detection */
	public const MAX_BAN_TARGETS = 500;
	/**
	 * An address is only blocked when it tried this many different passwords
	 * ({@see AttemptMapper::countsPerSource()}). Attempts with the shape of an
	 * app password count as none: a device with a revoked app password sends
	 * it over and over, and nobody guesses a generated one.
	 */
	public const MIN_PASSWORDS_TO_BLOCK = 4;

	public function __construct(
		private readonly CheckSettings $settings,
		private readonly AttemptMapper $attempts,
		private readonly RiskScorer $risk,
	) {
	}

	/**
	 * @param FailedLoginAttempt $signal
	 * @return list<DetectionDraft>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): iterable {
		$attempt = $signal->attempt;
		$uid = $attempt->uid;
		if ($uid === null || !in_array($attempt->kind, self::KINDS, true)) {
			return [];
		}
		$params = $this->settings->params(AccountUnderAttack::ID);
		$since = $attempt->time - (int)$params['window'];
		$stats = $this->attempts->stats('uid', [$uid], self::KINDS, $since);

		$limits = $this->risk->limits($attempt->source, [
			'min_failures' => [(int)$params['min_failures'], $stats->failures],
			'min_sources' => [(int)$params['min_sources'], $stats->distinctSources],
		]);
		if (!$limits->reached()) {
			return [];
		}
		$draft = new DetectionDraft(
			checkId: AccountUnderAttack::ID,
			uid: $uid,
			facts: [
				'failures' => $stats->failures,
				'sources' => $stats->distinctSources,
				'first' => $stats->first,
				'last' => $stats->last,
				'lastSource' => $attempt->source->ip,
			] + $limits->facts(),
			merge: DetectionDraft::MERGE_USER,
			userAgent: $signal->userAgent,
		);
		if ($this->settings->hasResponse(AccountUnderAttack::ID, ResponseType::Ban)) {
			$minimum = (int)$params['ban_min_failures'];
			foreach ($this->attempts->countsPerSource('uid', [$uid], self::KINDS, $since, self::MAX_BAN_TARGETS) as $ipKey => $counts) {
				// A device with an old saved password repeats one password; guessing tries many.
				$hostile = $counts['failures'] >= $minimum && $counts['passwords'] >= self::MIN_PASSWORDS_TO_BLOCK;
				$target = $hostile ? SourceKey::tryFromIpKey((string)$ipKey) : null;
				if ($target !== null) {
					$draft->addBanTarget($target);
				}
			}
		}
		// A merged detection runs its responses again: the protection is extended while the limits are reached.
		return [$draft];
	}
}
