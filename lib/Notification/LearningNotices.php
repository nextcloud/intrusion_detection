<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Learning\LearningService;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Notification\IManager as INotificationManager;

/**
 * Tells the administrators about the learning period:
 *
 * - a day before it ends, what the app would have done so far, with the
 *   actions "Start protecting now" and "Observe 7 more days";
 * - when protection starts automatically.
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
		private readonly Settings $settings,
		private readonly LearningService $learning,
		private readonly AdminRecipients $recipients,
		private readonly INotificationManager $notifications,
		private readonly DetectionMapper $detections,
		private readonly AdminLinks $links,
		private readonly ITimeFactory $timeFactory,
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
		$this->settings->setGlobal(GlobalSettings::LEARNING_NOTICE_SENT, $now);
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
	 * What learning mode held back since a time: detections that were only
	 * observed because of learning mode (not those of checks set to Observe),
	 * and how many different addresses they would have blocked.
	 *
	 * @return array{0: int, 1: int}
	 */
	private function summary(int $since): array {
		$detections = 0;
		$addresses = [];
		foreach ($this->detections->findList(new DetectionFilter(enforced: false, since: $since, limit: self::SUMMARY_LIMIT)) as $detection) {
			if (($detection->getExplanationData()['mode']['reason'] ?? null) !== ModeState::REASON_LEARNING) {
				continue;
			}
			$detections++;
			$ip = $detection->getIp();
			if ($ip !== null && in_array(ResponseType::Ban->value, array_column($detection->getActionList(), 'type'), true)) {
				$addresses[$ip] = true;
			}
		}
		return [$detections, count($addresses)];
	}
}
