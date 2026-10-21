<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack;
use OCA\IntrusionDetection\Check\Checks\StepUpRefusedClient;
use OCA\IntrusionDetection\Check\Checks\StepUpUnconfirmed;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUserManager;
use OCP\Notification\IManager as INotificationManager;

/**
 * Tells the affected user about a detection (concept section 11.1): a
 * notification and an email, both built by {@see UserMessages}, linking only
 * to the user's own security settings.
 *
 * Aggregated: at most one per check and user per interval (an hour; a day
 * for an account under attack). Later hits only raise a counter.
 *
 * Users without an email address are a normal case. They get the
 * notification only, and for severe detections the administrators are told
 * that the user could only be reached inside Nextcloud. Further ways to
 * reach such users belong in {@see self::unreachable()}.
 */
class UserAlerts {
	public const SUBJECT = 'user_detection';
	public const OBJECT_TYPE = 'user_detection';
	/** Counter key prefix; "@user:<uid>" fits the counter column */
	public const KEY_PREFIX = '@user:';
	public const DEFAULT_INTERVAL = 3600;
	/** @var array<string, int> checks that tell their users less often */
	public const INTERVALS = [AccountUnderAttack::ID => 86400, StepUpRefusedClient::ID => 86400, StepUpUnconfirmed::ID => 86400];
	/** Users without email: the administrators are told from this severity on */
	public const UNREACHABLE_MIN_SEVERITY = Severity::High;

	public const BELL_SENT = 'sent';
	public const BELL_AGGREGATED = 'aggregated';
	public const EMAIL_SENT = 'sent';
	public const EMAIL_AGGREGATED = 'aggregated';
	public const EMAIL_NO_ADDRESS = 'no_address';
	public const EMAIL_FAILED = 'failed';

	public function __construct(
		private readonly AlertMapper $alerts,
		private readonly INotificationManager $notifications,
		private readonly Mails $mails,
		private readonly UserMessages $messages,
		private readonly AdminNotices $adminNotices,
		private readonly IUserManager $userManager,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return ?array{bell: string, email: string, admins: int} null when the detection's account does not exist (any more)
	 */
	public function notify(Detection $detection): ?array {
		$uid = $detection->getUid();
		$user = $uid === null ? null : $this->userManager->get($uid);
		if ($uid === null || $user === null || !$user->isEnabled()) {
			return null;
		}
		$now = $this->timeFactory->getTime();
		$interval = self::INTERVALS[$detection->getCheckId()] ?? self::DEFAULT_INTERVAL;
		[, $first] = $this->alerts->hit($detection->getCheckId(), self::KEY_PREFIX . $uid, intdiv($now, $interval), $detection->getId(), $now);
		if (!$first) {
			return ['bell' => self::BELL_AGGREGATED, 'email' => self::EMAIL_AGGREGATED, 'admins' => 0];
		}

		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser($uid)
			->setDateTime(new \DateTime('@' . $now))
			->setObject(self::OBJECT_TYPE, (string)$detection->getId())
			->setSubject(self::SUBJECT, ['detection' => $detection->getId()]);
		$this->notifications->notify($notification);

		$address = (string)$user->getEMailAddress();
		if ($address === '') {
			$email = self::EMAIL_NO_ADDRESS;
		} else {
			$email = $this->mails->send($user, $this->messages->mail($detection, $user)) ? self::EMAIL_SENT : self::EMAIL_FAILED;
		}
		$admins = $email === self::EMAIL_SENT ? 0 : $this->unreachable($detection, $uid, $email);
		return ['bell' => self::BELL_SENT, 'email' => $email, 'admins' => $admins];
	}

	/**
	 * The user could only be told inside Nextcloud. For severe detections the
	 * administrators are told, so that they can reach out.
	 *
	 * @return int how many administrators were notified
	 */
	private function unreachable(Detection $detection, string $uid, string $email): int {
		$severity = Severity::tryFrom($detection->getSeverity());
		if ($severity === null || !$severity->atLeast(self::UNREACHABLE_MIN_SEVERITY)) {
			return 0;
		}
		return $this->adminNotices->userUnreachable(
			$uid,
			$detection->getId(),
			$detection->getCheckId(),
			$email === self::EMAIL_NO_ADDRESS ? AdminNotices::REASON_NO_ADDRESS : AdminNotices::REASON_MAIL_FAILED,
		);
	}
}
