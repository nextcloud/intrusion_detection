<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Db\StatsMapper;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\State\AppState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Notification\IManager as INotificationManager;

/**
 * Tells the administrators about the learning period:
 *
 * - a day before it ends, what the app would have done so far, with the
 *   actions "Start protecting now" and "Observe 7 more days";
 * - when protection starts automatically, linking to the recap of the
 *   period on the overview of the admin page.
 *
 * The notice is sent once per learning period (`learning_notice_sent`;
 * starting or extending learning mode resets it). Its actions open the admin
 * page, as both change protection and need the password. Starting,
 * extending or ending learning mode removes it
 * ({@see LearningService}).
 */
class LearningNotices {
	public const OBJECT_TYPE = 'learning';
	public const OBJECT_ID = 'period';
	/** The notice is sent when this little of the learning period is left */
	public const NOTICE_BEFORE = 86400;
	public const EXTEND_DAYS = 7;
	/** The notice summarises the observed detections of this many days */
	public const SUMMARY_DAYS = 7;
	/** At most this many detections are read for the summary */
	public const SUMMARY_LIMIT = 5000;

	public function __construct(
		private readonly LearningService $learning,
		private readonly AdminRecipients $recipients,
		private readonly INotificationManager $notifications,
		private readonly StatsMapper $stats,
		private readonly AdminLinks $links,
		private readonly ITimeFactory $timeFactory,
		private readonly AppState $state,
	) {
	}

	/**
	 * Send the "learning ends tomorrow" notice once, when it is due.
	 *
	 * @return bool whether it was sent now
	 */
	public function sendEndingNoticeIfDue(): bool {
		$now = $this->timeFactory->getTime();
		$until = $this->learning->until();
		if (!$this->learning->isActive() || $until - $now > self::NOTICE_BEFORE || $this->learning->isEndingNoticePending()) {
			return false;
		}
		[$detections, $blocks] = $this->summary($now - self::SUMMARY_DAYS * 86400);
		$this->state->setInt(LearningService::NOTICE_STATE, $now);
		foreach ($this->recipients->users() as $user) {
			$notification = $this->notifications->createNotification();
			$notification->setApp(Application::APP_ID)
				->setUser($user->getUID())
				->setDateTime(new \DateTime('@' . $now))
				->setObject(self::OBJECT_TYPE, self::OBJECT_ID)
				->setSubject(Notifier::SUBJECT_LEARNING_ENDS, [
					'until' => $until,
					'days' => self::SUMMARY_DAYS,
					'detections' => $detections,
					'blocks' => $blocks,
				]);
			$protect = $notification->createAction();
			$protect->setLabel(Notifier::ACTION_PROTECT)
				->setLink($this->links->adminPage(), 'WEB')
				->setPrimary(true);
			$notification->addAction($protect);
			$extend = $notification->createAction();
			$extend->setLabel(Notifier::ACTION_EXTEND)
				->setLink($this->links->adminPage(), 'WEB');
			$notification->addAction($extend);
			$this->notifications->notify($notification);
		}
		return true;
	}

	/**
	 * Learning mode ended by itself: tell the administrators.
	 */
	public function protectionStarted(): void {
		$now = $this->timeFactory->getTime();
		foreach ($this->recipients->users() as $user) {
			$notification = $this->notifications->createNotification();
			$notification->setApp(Application::APP_ID)
				->setUser($user->getUID())
				->setDateTime(new \DateTime('@' . $now))
				->setObject(self::OBJECT_TYPE, 'started-' . $now)
				->setSubject(Notifier::SUBJECT_PROTECTION_STARTED);
			$this->notifications->notify($notification);
		}
	}

	/**
	 * What learning mode held back since a time: the detections, and how
	 * many different addresses they would have blocked.
	 *
	 * @return array{0: int, 1: int}
	 */
	private function summary(int $since): array {
		$heldBack = $this->stats->heldBackByLearning($since, null, self::SUMMARY_LIMIT);
		return [$heldBack['detections'], count($heldBack['addresses'])];
	}
}
