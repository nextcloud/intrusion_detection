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
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\AccountProtection;
use OCA\IntrusionDetection\Response\ResponseEngine;

/**
 * Detects one account attacked from many places (concept section 10.3)
 * after each failed login whose login name belongs to an account.
 *
 * The detection is about the account, so it has no single source address.
 * While failures continue, an account that is already protected stays
 * protected until `protect_duration` after the last failure, even when the
 * numbers fall below the thresholds again.
 */
class AccountUnderAttackDetector {
	public const KINDS = [AttemptKind::PasswordLogin, AttemptKind::AppPassword];
	/** Blocking blocks at most this many addresses per detection */
	public const MAX_BAN_TARGETS = 500;

	public function __construct(
		private readonly Settings $settings,
		private readonly AttemptMapper $attempts,
		private readonly ResponseEngine $engine,
		private readonly AccountProtection $protection,
	) {
	}

	public function detect(AttemptRecord $attempt, ?string $userAgent): void {
		$uid = $attempt->uid;
		if ($uid === null || !in_array($attempt->kind, self::KINDS, true)) {
			return;
		}
		$state = $this->settings->modeState(AccountUnderAttack::ID);
		if (!$state->runs()) {
			return;
		}
		$params = $this->settings->params(AccountUnderAttack::ID);
		$since = $attempt->time - (int)$params['window'];
		$stats = $this->attempts->stats('uid', [$uid], self::KINDS, $since);

		if ($stats->failures >= (int)$params['min_failures'] && $stats->distinctSources >= (int)$params['min_sources']) {
			$draft = new DetectionDraft(
				checkId: AccountUnderAttack::ID,
				uid: $uid,
				facts: [
					'failures' => $stats->failures,
					'sources' => $stats->distinctSources,
					'first' => $stats->first,
					'last' => $stats->last,
					'lastSource' => $attempt->source->ip,
				],
				merge: DetectionDraft::MERGE_USER,
				userAgent: $userAgent,
			);
			if ($this->settings->hasResponse(AccountUnderAttack::ID, ResponseType::Ban)) {
				$minimum = (int)$params['ban_min_failures'];
				foreach ($this->attempts->failuresPerSource('uid', $uid, self::KINDS, $since, self::MAX_BAN_TARGETS) as $ipKey => $failures) {
					$target = $failures >= $minimum ? SourceKey::tryFromIpKey($ipKey) : null;
					if ($target !== null) {
						$draft->addBanTarget($target);
					}
				}
			}
			$this->engine->handle($draft);
			return;
		}

		if ($state->acts()
			&& $this->settings->hasResponse(AccountUnderAttack::ID, ResponseType::ProtectAccount)
			&& $this->protection->isProtected($uid)) {
			$this->protection->protect($uid, $attempt->time + (int)$params['protect_duration']);
		}
	}
}
