<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Blocklist\Db\BlocklistStatMapper;
use OCA\IntrusionDetection\Confirm\AbandonedLogins;
use OCA\IntrusionDetection\Confirm\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\DetectionAccountMapper;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\IPurges;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Db\UserDailyMapper;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\KnownDevice\Db\KnownDeviceMapper;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\LoginHistory\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Notification\Db\AlertMapper;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\Response\AccountProtection;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\Db\FlagMapper;
use OCA\IntrusionDetection\Response\Db\ProtectedAccountMapper;
use OCA\IntrusionDetection\Response\Db\ResetSuppressionMapper;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\ResetMailSuppressor;
use OCA\IntrusionDetection\Takeover\Db\LockLinkMapper;
use OCA\IntrusionDetection\Takeover\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Takeover\LockLinks;
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCA\IntrusionDetection\TrustedNetwork\Db\TrustedNetworkMapper;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJob;
use OCP\BackgroundJob\TimedJob;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Lets every owner of a table delete what is past its retention, every five
 * minutes. Each owner keeps its own retention and deletes in batches; an
 * owner that fails is logged without skipping the others.
 */
class Cleanup extends TimedJob {
	/**
	 * The owners in the order they run, with the tables each one purges.
	 * An owner is only built when the job runs.
	 *
	 * @var array<class-string<IPurges>, list<string>>
	 */
	public const PURGES = [
		// Writes the counts kept in the memory cache, before their tables are purged.
		PendingCounts::class => [],
		// Flags the addresses of ended blocks before it deletes old ones.
		BanService::class => [BanMapper::TABLE],
		// Also notes whether the attempts table is flooded.
		AttemptRecorder::class => [AttemptMapper::TABLE],
		LoginMapper::class => [LoginMapper::TABLE],
		// A detection's accounts go with it; old hours go into the running totals.
		DetectionTotals::class => [DetectionMapper::TABLE, DetectionAccountMapper::TABLE, DetectionTotals::TABLE],
		FlaggedSources::class => [FlagMapper::TABLE],
		AccountProtection::class => [ProtectedAccountMapper::TABLE],
		AlertMapper::class => [AlertMapper::TABLE],
		ResetMailSuppressor::class => [ResetSuppressionMapper::TABLE],
		TokenOriginMapper::class => [TokenOriginMapper::TABLE],
		TrustedNetworks::class => [TrustedNetworkMapper::TABLE],
		// Ends the logins left waiting past their deadline, before their sessions' rows expire.
		AbandonedLogins::class => [],
		UnconfirmedSessions::class => [StepUpSessionMapper::TABLE],
		KnownDevices::class => [KnownDeviceMapper::TABLE],
		LoginHistory::class => [LoginHistoryMapper::TABLE],
		SecurityChangeLog::class => [SecurityChangeMapper::TABLE],
		LockLinks::class => [LockLinkMapper::TABLE],
		FailedLoginStats::class => [UserDailyMapper::TABLE],
		BlocklistStatMapper::class => [BlocklistStatMapper::TABLE],
	];

	public function __construct(
		ITimeFactory $time,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
		parent::__construct($time);
		$this->setInterval(300);
		$this->setTimeSensitivity(IJob::TIME_SENSITIVE);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		$now = $this->time->getTime();
		foreach (array_keys(self::PURGES) as $owner) {
			try {
				$purger = $this->container->get($owner);
				if ($purger instanceof IPurges) {
					$purger->purge($now);
				}
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not clean up {step}', ['step' => $owner, 'exception' => $e]);
			}
		}
	}
}
