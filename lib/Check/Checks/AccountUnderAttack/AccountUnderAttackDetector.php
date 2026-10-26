<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\AccountUnderAttack;

use OCA\IntrusionDetection\Check\Checks\SharedAddress\SharedAddress;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\Cooldown;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanResult;
use OCA\IntrusionDetection\Response\BanService;
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
 * Once it fired, the check cools down for the account ({@see Cooldown}):
 * within the period, a failure only counts as a hit of the detection, and
 * its address alone is judged, and blocked when blocking is on.
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
		private readonly Cooldown $cooldown,
		private readonly BanService $bans,
	) {
	}

	/**
	 * @param FailedLoginAttempt $signal
	 * @return \Generator<int, DetectionDraft, ?Detection, void>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): \Generator {
		$attempt = $signal->attempt;
		$uid = $attempt->uid;
		if ($uid === null || !in_array($attempt->kind, self::KINDS, true)) {
			return;
		}
		$params = $this->settings->params(AccountUnderAttack::ID);
		$since = $attempt->time - (int)$params['window'];
		$detectionId = $this->cooldown->cooled(AccountUnderAttack::ID, [$uid], $mode, $attempt->time);
		if ($detectionId !== null) {
			yield from $this->banJoiningSource($attempt, $uid, $mode, (int)$params['ban_min_failures'], $since, $detectionId);
			return;
		}
		$stats = $this->attempts->stats('uid', [$uid], self::KINDS, $since);

		$limits = $this->risk->limits($attempt->source, [
			'min_failures' => [(int)$params['min_failures'], $stats->failures],
			'min_sources' => [(int)$params['min_sources'], $stats->distinctSources],
		]);
		if (!$limits->reached()) {
			$this->cooldown->stop(AccountUnderAttack::ID, [$uid], $mode);
			return;
		}
		$draft = new DetectionDraft(
			checkId: AccountUnderAttack::ID,
			uid: $uid,
			facts: new AccountUnderAttackFacts(
				failures: $stats->failures,
				sources: $stats->distinctSources,
				lastSource: $attempt->source->ip,
				common: new CommonFacts(first: $stats->first, last: $stats->last, risk: $limits->facts()),
			),
			merge: DetectionDraft::MERGE_USER,
			userAgent: $signal->userAgent,
		);
		if ($this->settings->hasResponse(AccountUnderAttack::ID, ResponseType::Ban)) {
			$minimum = (int)$params['ban_min_failures'];
			foreach ($this->attempts->countsPerSource('uid', [$uid], self::KINDS, $since, self::MAX_BAN_TARGETS) as $ipKey => $counts) {
				$target = self::hostile($counts, $minimum) ? SourceKey::tryFromIpKey((string)$ipKey) : null;
				if ($target !== null) {
					$draft->addBanTarget($target);
				}
			}
		}
		// A merged detection runs its responses again: the protection is extended while the limits are reached.
		$this->cooldown->start(AccountUnderAttack::ID, [$uid], $mode, yield $draft);
	}

	/**
	 * An address failing for the account while the check cools down: blocked
	 * once it is hostile, like the addresses blocked by the detection, and
	 * reported when the block is held back for a shared address or a proxy.
	 *
	 * @return \Generator<int, DetectionDraft, ?Detection, void>
	 */
	private function banJoiningSource(#[\SensitiveParameter] AttemptRecord $attempt, string $uid, ModeState $mode, int $minimum, int $since, string $detectionId): \Generator {
		if (!$mode->acts() || !$this->settings->hasResponse(AccountUnderAttack::ID, ResponseType::Ban)) {
			return;
		}
		$source = $attempt->source;
		$counts = $this->attempts->countsPerSource('uid', [$uid], self::KINDS, $since, 1, $source->ipKey)[$source->ipKey] ?? null;
		if ($counts === null || !self::hostile($counts, $minimum)) {
			return;
		}
		$result = $this->bans->ban($source, AccountUnderAttack::ID, $detectionId, null, $uid);
		if (($result->outcome === BanResult::SKIPPED_SHARED || $result->outcome === BanResult::SKIPPED_PROXY) && $this->bans->firstReport($source)) {
			yield SharedAddress::draft($source, $result->sharedUsers, AccountUnderAttack::ID, $result->outcome === BanResult::SKIPPED_PROXY);
		}
	}

	/**
	 * A device with an old saved password repeats one password; guessing tries many.
	 *
	 * @param array{failures: int, names: int, passwords: int} $counts
	 */
	private static function hostile(array $counts, int $minimum): bool {
		return $counts['failures'] >= $minimum && $counts['passwords'] >= self::MIN_PASSWORDS_TO_BLOCK;
	}
}
