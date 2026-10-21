<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\FlagMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Db\ProtectedAccountMapper;
use OCA\IntrusionDetection\Db\ResetSuppressionMapper;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
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

	public function __construct(
		ITimeFactory $time,
		private readonly AttemptMapper $attempts,
		private readonly LoginMapper $logins,
		private readonly DetectionMapper $detections,
		private readonly BanMapper $bans,
		private readonly FlagMapper $flags,
		private readonly Settings $settings,
		private readonly IDBConnection $db,
		private readonly ProtectedAccountMapper $protectedAccounts,
		private readonly AlertMapper $alerts,
		private readonly ResetSuppressionMapper $resetSuppressions,
	) {
		parent::__construct($time);
		$this->setInterval(300);
		$this->setTimeSensitivity(IJob::TIME_SENSITIVE);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		$now = $this->time->getTime();
		$this->attempts->deleteOlderThan($now - AttemptRecorder::RETENTION);
		$this->logins->deleteOlderThan(intdiv($now - 86400, 3600));
		$this->detections->deleteCreatedBefore($now - $this->settings->getInt(GlobalSettings::RETENTION_DETECTIONS_DAYS) * 86400);
		$this->bans->deleteEndedBefore($now - max(self::BAN_HISTORY, $this->settings->getInt(GlobalSettings::BAN_HISTORY_DAYS) * 86400));
		$this->flags->deleteExpired($now);
		$this->protectedAccounts->deleteExpired($now);
		$this->alerts->deleteOlderThan($now - self::ALERT_RETENTION);
		$this->resetSuppressions->deleteExpired($now);
		$this->updateFloodState($now);
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
