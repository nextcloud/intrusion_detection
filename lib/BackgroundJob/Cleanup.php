<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
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
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJob;
use OCP\BackgroundJob\TimedJob;
use OCP\IDBConnection;

/**
 * Deletes everything past its retention, every five minutes, and notices
 * when the attempts table is flooded.
 */
class Cleanup extends TimedJob {
	/** Ended bans are kept this long, for escalation */
	public const BAN_HISTORY = 30 * 86400;
	/** Alert counters are kept as long as their notifications are likely to be read */
	public const ALERT_RETENTION = 30 * 86400;
	/** Where app passwords came from is kept this long */
	public const TOKEN_ORIGIN_RETENTION = 30 * 86400;
	/** Ended blocks flagged per run at most */
	public const ENDED_BANS_PER_RUN = 1000;

	public function __construct(
		ITimeFactory $time,
		private readonly AttemptMapper $attempts,
		private readonly LoginMapper $logins,
		private readonly BanMapper $bans,
		private readonly FlagMapper $flags,
		private readonly Settings $settings,
		private readonly IDBConnection $db,
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
	) {
		parent::__construct($time);
		$this->setInterval(300);
		$this->setTimeSensitivity(IJob::TIME_SENSITIVE);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		$now = $this->time->getTime();
		$this->flagEndedBans($now);
		$this->attempts->deleteOlderThan($now - AttemptRecorder::RETENTION);
		$this->logins->deleteOlderThan(intdiv($now - 86400, 3600));
		$this->detectionTotals->deleteCreatedBefore($now - $this->settings->getInt(GlobalSettings::RETENTION_DETECTIONS_DAYS) * 86400);
		$this->bans->deleteEndedBefore($now - max(self::BAN_HISTORY, $this->settings->getInt(GlobalSettings::BAN_HISTORY_DAYS) * 86400));
		$this->flags->deleteExpired($now);
		$this->protectedAccounts->deleteExpired($now);
		$this->alerts->deleteOlderThan($now - self::ALERT_RETENTION);
		$this->resetMails->deleteExpired();
		$this->tokenOrigins->deleteOlderThan($now - self::TOKEN_ORIGIN_RETENTION);
		$this->trustedNetworks->deleteExpired($now);
		$this->abandonedLogins->end();
		$this->stepUpSessions->deleteExpired($now);
		$this->knownDevices->deleteExpired();
		$this->loginHistory->deleteOlderThan($now - $this->settings->getInt(GlobalSettings::HISTORY_RETENTION_DAYS) * 86400);
		$this->securityChanges->deleteOlderThan($now - $this->settings->getInt(GlobalSettings::HISTORY_RETENTION_DAYS) * 86400);
		$this->securityChanges->forgetAddressesBefore($now - SecurityChangeLog::ADDRESS_TTL);
		$this->lockLinks->deleteExpired($now);
		$this->failedLoginStats->deleteExpired();
		$this->updateFloodState($now);
	}

	/**
	 * Flag the addresses of blocks that ended since the last run, before
	 * ended blocks are deleted. At most ENDED_BANS_PER_RUN per run; the rest
	 * follow at the next. Blocks that ended longer ago than a flag lasts are
	 * skipped: their flag would have ended too. The progress is only written
	 * when something ended.
	 */
	private function flagEndedBans(int $now): void {
		$since = max($this->settings->getInt(GlobalSettings::BANS_FLAGGED_UNTIL), $now - $this->settings->getInt(GlobalSettings::FLAG_DURATION));
		$ended = $this->bans->findEndedBetween($since, $now, self::ENDED_BANS_PER_RUN);
		if ($ended === []) {
			return;
		}
		foreach ($ended as $ban) {
			$this->flaggedSources->flagEndedBan($ban);
		}
		// Blocks that end in the same second as the last one flagged are looked at again; flagging is idempotent.
		$this->settings->setGlobal(GlobalSettings::BANS_FLAGGED_UNTIL, count($ended) < self::ENDED_BANS_PER_RUN ? $now : $ended[count($ended) - 1]->getExpiresAt() - 1);
	}

	private function updateFloodState(int $now): void {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*'))->from(AttemptMapper::TABLE);
		$result = $qb->executeQuery();
		$rows = (int)$result->fetchOne();
		$result->closeCursor();
		$flooded = $rows > AttemptRecorder::FLOOD_ROWS;
		$until = $this->settings->getInt(GlobalSettings::ATTEMPTS_FLOOD_UNTIL);
		if ($flooded) {
			$this->settings->setGlobal(GlobalSettings::ATTEMPTS_FLOOD_UNTIL, $now + 600);
		} elseif ($until > 0) {
			$this->settings->setGlobal(GlobalSettings::ATTEMPTS_FLOOD_UNTIL, 0);
		}
	}
}
