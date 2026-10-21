<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Learning;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Learning mode: while it lasts, every check set to Protect only observes,
 * except checks that only notify and (by default) decoys. It starts for seven days when the app is
 * installed and can be started again for 1 to 30 days at any time.
 *
 * Starting, extending and ending it is written to the audit log with who
 * did it, and is no administration change for the admin change check: the
 * page shows the learning period to every administrator, and the app
 * changes it on its own when it is installed and when the period is over.
 * A change of `learning_until` made around the app is still reported by
 * the config watch.
 */
class LearningService {
	public const MIN_DAYS = 1;
	public const MAX_DAYS = 30;

	public function __construct(
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
		private readonly AuditLogger $audit,
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
	 * Start (or restart) learning mode for a number of days.
	 */
	public function start(int $days, string $actor): int {
		if ($days < self::MIN_DAYS || $days > self::MAX_DAYS) {
			throw new \InvalidArgumentException('Learning mode lasts 1 to 30 days');
		}
		$until = $this->timeFactory->getTime() + $days * 86400;
		$this->settings->setGlobal(GlobalSettings::LEARNING_UNTIL, $until, reported: false);
		$this->settings->setGlobal(GlobalSettings::LEARNING_STARTED_AT, $this->timeFactory->getTime());
		$this->settings->setGlobal(GlobalSettings::LEARNING_NOTICE_SENT, 0);
		$this->audit->log('learning mode started for %s days by %s', ['days' => $days, 'actor' => $actor]);
		return $until;
	}

	/**
	 * Add days to a running learning period (or start one).
	 */
	public function extend(int $days, string $actor): int {
		if (!$this->isActive()) {
			$this->settings->setGlobal(GlobalSettings::LEARNING_STARTED_AT, $this->timeFactory->getTime());
		}
		$base = max($this->until(), $this->timeFactory->getTime());
		$until = min($base + $days * 86400, $this->timeFactory->getTime() + self::MAX_DAYS * 86400);
		$this->settings->setGlobal(GlobalSettings::LEARNING_UNTIL, $until, reported: false);
		$this->settings->setGlobal(GlobalSettings::LEARNING_NOTICE_SENT, 0);
		$this->audit->log('learning mode extended by %s days by %s', ['days' => $days, 'actor' => $actor]);
		return $until;
	}

	/**
	 * End learning mode now: checks set to Protect start acting.
	 */
	public function stop(string $actor): void {
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
		$this->audit->log('learning mode ended automatically; protection is active', []);
		return true;
	}
}
