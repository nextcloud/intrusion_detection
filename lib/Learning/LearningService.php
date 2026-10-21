<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Learning;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\DecoyCredential;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Notification\LearningNotices;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Notification\IManager as INotificationManager;

/**
 * Learning mode: while it lasts, every check set to Protect only observes,
 * except checks that only notify and (by default) decoys. It starts for seven days when the app is
 * installed and can be started again for 1 to 30 days at any time.
 *
 * Starting, extending and ending it is written to the audit log with who
 * did it. An administrator (page or occ) who moves its end to a later date
 * keeps protection weakened for longer, like switching a check to Observe:
 * that is also reported as an administration change, high when the
 * instance was protecting before, medium when it was learning already.
 * Ending or shortening it, and the app's own changes at installation and
 * when the period is over, are not. A change of `learning_until` made
 * around the app is reported by the config watch.
 *
 * One learning period lasts at most MAX_DAYS from its start, however often
 * it is started again or extended while it runs ({@see LearningLimitException}).
 *
 * Every change of the period removes the "learning ends tomorrow" notice:
 * it was about the period before.
 */
class LearningService {
	public const MIN_DAYS = 1;
	public const MAX_DAYS = 30;

	public function __construct(
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
		private readonly AuditLogger $audit,
		private readonly INotificationManager $notifications,
	) {
	}

	public function isActive(): bool {
		return $this->settings->isLearning();
	}

	public function until(): int {
		return $this->settings->learningUntil();
	}

	public function daysLeft(): int {
		$left = $this->until() - $this->timeFactory->getTime();
		return $left <= 0 ? 0 : (int)ceil($left / 86400);
	}

	/**
	 * Start (or restart) learning mode for a number of days. While a period
	 * runs, it sets that period's end; the period keeps its start.
	 *
	 * @throws LearningLimitException when the end would be more than MAX_DAYS after the period's start
	 */
	public function start(int $days, string $actor): int {
		if ($days < self::MIN_DAYS || $days > self::MAX_DAYS) {
			throw new \InvalidArgumentException('Learning mode lasts 1 to 30 days');
		}
		$until = $this->setUntil($this->timeFactory->getTime() + $days * 86400);
		$this->audit->log('learning mode started for %s days by %s', ['days' => $days, 'actor' => $actor]);
		return $until;
	}

	/**
	 * Add days to a running learning period (or start one).
	 *
	 * @throws LearningLimitException when the end would be more than MAX_DAYS after the period's start
	 */
	public function extend(int $days, string $actor): int {
		$until = $this->setUntil(max($this->until(), $this->timeFactory->getTime()) + $days * 86400);
		$this->audit->log('learning mode extended by %s days by %s', ['days' => $days, 'actor' => $actor]);
		return $until;
	}

	/**
	 * When the running learning period started, 0 while protecting.
	 */
	public function startedAt(): int {
		if (!$this->isActive()) {
			return 0;
		}
		$started = $this->settings->getInt(GlobalSettings::LEARNING_STARTED_AT);
		return $started > 0 ? $started : $this->settings->getInt(GlobalSettings::INSTALLED_AT);
	}

	/**
	 * The latest end a learning period that starts now, or the running one, may have.
	 */
	public function latestUntil(): int {
		$started = $this->startedAt();
		return ($started > 0 ? $started : $this->timeFactory->getTime()) + self::MAX_DAYS * 86400;
	}

	/**
	 * Set the end of the learning period, starting one while protecting.
	 * A later end than before is an administration change. The "learning
	 * ends tomorrow" notice is sent again before the new end.
	 */
	private function setUntil(int $until): int {
		$latest = $this->latestUntil();
		if ($until > $latest) {
			throw new LearningLimitException($latest, $this->startedAt());
		}
		$protecting = !$this->isActive();
		$before = $this->until();
		$this->settings->setGlobal(GlobalSettings::LEARNING_UNTIL, $until, reported: $until > $before);
		if ($protecting) {
			$this->settings->setGlobal(GlobalSettings::LEARNING_STARTED_AT, $this->timeFactory->getTime());
		}
		$this->settings->setGlobal(GlobalSettings::LEARNING_NOTICE_SENT, 0);
		$this->dismissEndingNotice();
		return $until;
	}

	/**
	 * End learning mode now: checks set to Protect start acting.
	 */
	public function stop(string $actor): void {
		$this->dismissEndingNotice();
		if ($this->until() === 0) {
			return;
		}
		$this->settings->setGlobal(GlobalSettings::LEARNING_UNTIL, 0, reported: false);
		$this->audit->log('learning mode ended by %s', ['actor' => $actor]);
	}

	/**
	 * Start the first learning period when the app is installed.
	 */
	public function startAtInstall(int $now): void {
		$this->settings->setGlobal(GlobalSettings::LEARNING_UNTIL, $now + GlobalSettings::LEARNING_DEFAULT_PERIOD, reported: false);
		$this->settings->setGlobal(GlobalSettings::LEARNING_STARTED_AT, $now);
		$this->audit->log('learning mode started for %s days at installation', ['days' => intdiv(GlobalSettings::LEARNING_DEFAULT_PERIOD, 86400)]);
	}

	/**
	 * Called by the background job: once the period is over, clear it, so the
	 * status says "Protecting" rather than "learning ended at …".
	 *
	 * @return bool whether learning mode ended just now
	 */
	public function expireIfDue(): bool {
		$until = $this->until();
		if ($until === 0 || $until > $this->timeFactory->getTime()) {
			return false;
		}
		$this->settings->setGlobal(GlobalSettings::LEARNING_UNTIL, 0, reported: false);
		$this->dismissEndingNotice();
		$this->audit->log('learning mode ended automatically; protection is active', []);
		return true;
	}

	/**
	 * Whether the "learning ends tomorrow" notice was sent for the running
	 * learning period, which nobody started, extended or ended since.
	 */
	public function isEndingNoticePending(): bool {
		return $this->isActive() && $this->settings->getInt(GlobalSettings::LEARNING_NOTICE_SENT) > 0;
	}

	/**
	 * Whether an address that uses a decoy is blocked right now. While
	 * learning, this is the only block a check makes.
	 */
	public function decoysBlock(): bool {
		return $this->settings->effectiveMode(DecoyCredential::ID) === Mode::Protect
			&& $this->settings->hasResponse(DecoyCredential::ID, ResponseType::Ban);
	}

	/**
	 * Remove the "learning ends tomorrow" notice for every administrator.
	 */
	private function dismissEndingNotice(): void {
		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setObject(LearningNotices::OBJECT_TYPE, LearningNotices::OBJECT_ID);
		$this->notifications->markProcessed($notification);
	}
}
