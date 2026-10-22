<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\AbandonedLogins;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\FlagMapper;
use OCA\IntrusionDetection\Db\LockLinkMapper;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Db\ProtectedAccountMapper;
use OCA\IntrusionDetection\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Db\TrustedNetworkMapper;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\ResetMailSuppressor;
use OCA\IntrusionDetection\State\AppState;
use OCA\IntrusionDetection\State\HotState;
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJob;
use OCP\BackgroundJob\TimedJob;
use Psr\Log\LoggerInterface;

/**
 * Deletes everything past its retention, every five minutes, and notices
 * when the attempts table is flooded. Deletes run in batches, and a step
 * that fails is logged without skipping the others.
 */
class Cleanup extends TimedJob {
	/** Blocks that ended up to this time have been flagged */
	public const BANS_FLAGGED_STATE = 'bans_flagged_until';
	/** Ended bans are kept this long, for escalation */
	public const BAN_HISTORY = 30 * 86400;
	/** Alert counters are kept as long as their notifications are likely to be read */
	public const ALERT_RETENTION = 30 * 86400;
	/** Where app passwords came from is kept this long */
	public const TOKEN_ORIGIN_RETENTION = 30 * 86400;
	/** Ended blocks flagged per run at most */
	public const ENDED_BANS_PER_RUN = 1000;
	/**
	 * Previous email addresses are forgotten for the changes of this period
	 * before their time is up; older ones were forgotten by earlier runs.
	 */
	public const ADDRESS_LOOK_BACK = 7 * 86400;

	public function __construct(
		ITimeFactory $time,
		private readonly AttemptMapper $attempts,
		private readonly LoginMapper $logins,
		private readonly BanMapper $bans,
		private readonly FlagMapper $flags,
		private readonly AppSettings $settings,
		private readonly ProtectedAccountMapper $protectedAccounts,
		private readonly AlertMapper $alerts,
		private readonly ResetMailSuppressor $resetMails,
		private readonly TokenOriginMapper $tokenOrigins,
		private readonly TrustedNetworkMapper $trustedNetworks,
		private readonly StepUpSessionMapper $stepUpSessions,
		private readonly DetectionTotals $detectionTotals,
		private readonly KnownDevices $knownDevices,
		private readonly LoginHistoryMapper $loginHistory,
		private readonly SecurityChangeMapper $securityChanges,
		private readonly LockLinkMapper $lockLinks,
		private readonly FailedLoginStats $failedLoginStats,
		private readonly AbandonedLogins $abandonedLogins,
		private readonly FlaggedSources $flaggedSources,
		private readonly LoggerInterface $logger,
		private readonly AppState $state,
		private readonly HotState $hotState,
	) {
		parent::__construct($time);
		$this->setInterval(300);
		$this->setTimeSensitivity(IJob::TIME_SENSITIVE);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		$now = $this->time->getTime();
		$retainedSince = $now - $this->settings->retentionDays() * 86400;
		$steps = [
			// Before ended blocks are deleted below.
			'ended_bans' => fn () => $this->flagEndedBans($now),
			'attempts' => fn (): int => $this->attempts->deleteOlderThan($now - AttemptRecorder::RETENTION),
			'flood_state' => fn () => $this->updateFloodState($now),
			'logins' => fn (): int => $this->logins->deleteOlderThan(intdiv($now - 86400, 3600)),
			'detections' => fn (): int => $this->detectionTotals->deleteCreatedBefore($retainedSince),
			'detection_totals' => fn (): int => $this->detectionTotals->retireBefore($now - DetectionTotals::ROLLUP_DAYS * 86400),
			'bans' => fn (): int => $this->bans->deleteEndedBefore($now - max(self::BAN_HISTORY, $this->settings->banHistoryDays() * 86400)),
			'flags' => fn (): int => $this->flags->deleteExpired($now),
			'protected_accounts' => fn (): int => $this->protectedAccounts->deleteExpired($now),
			'alerts' => fn (): int => $this->alerts->deleteOlderThan($now - self::ALERT_RETENTION),
			'reset_suppressions' => fn () => $this->resetMails->deleteExpired(),
			'token_origins' => fn (): int => $this->tokenOrigins->deleteOlderThan($now - self::TOKEN_ORIGIN_RETENTION),
			'trusted_networks' => fn (): int => $this->trustedNetworks->deleteExpired($now),
			'abandoned_logins' => fn () => $this->abandonedLogins->end(),
			'step_up_sessions' => fn (): int => $this->stepUpSessions->deleteExpired($now),
			'known_devices' => fn (): int => $this->knownDevices->deleteExpired(),
			'login_history' => fn (): int => $this->loginHistory->deleteOlderThan($retainedSince),
			'security_changes' => fn (): int => $this->securityChanges->deleteOlderThan($retainedSince),
			'security_change_addresses' => fn (): int => $this->securityChanges->forgetAddressesBefore(
				$now - SecurityChangeLog::ADDRESS_TTL,
				$now - SecurityChangeLog::ADDRESS_TTL - self::ADDRESS_LOOK_BACK,
			),
			'lock_links' => fn (): int => $this->lockLinks->deleteExpired($now),
			'failed_login_stats' => fn (): int => $this->failedLoginStats->deleteExpired(),
		];
		foreach ($steps as $name => $step) {
			try {
				$step();
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not clean up {step}', ['step' => $name, 'exception' => $e]);
			}
		}
	}

	/**
	 * Flag the addresses of blocks that ended since the last run, before
	 * ended blocks are deleted. At most ENDED_BANS_PER_RUN per run; the rest
	 * follow at the next. Blocks that ended longer ago than a flag lasts are
	 * skipped: their flag would have ended too. The progress is only written
	 * when something ended.
	 */
	private function flagEndedBans(int $now): void {
		$since = max($this->state->getInt(self::BANS_FLAGGED_STATE), $now - FlaggedSources::DURATION);
		$ended = $this->bans->findEndedBetween($since, $now, self::ENDED_BANS_PER_RUN);
		if ($ended === []) {
			return;
		}
		foreach ($ended as $ban) {
			$this->flaggedSources->flagEndedBan($ban);
		}
		// Blocks that end in the same second as the last one flagged are looked at again; flagging is idempotent.
		$this->state->setInt(self::BANS_FLAGGED_STATE, count($ended) < self::ENDED_BANS_PER_RUN ? $now : $ended[count($ended) - 1]->getExpiresAt() - 1);
	}

	private function updateFloodState(int $now): void {
		$flooded = $this->attempts->hasMoreThan(AttemptRecorder::FLOOD_ROWS);
		$until = $this->hotState->attemptsFloodUntil();
		if ($flooded) {
			$this->hotState->setAttemptsFloodUntil($now + 600);
		} elseif ($until > 0) {
			$this->hotState->setAttemptsFloodUntil(0);
		}
	}
}
