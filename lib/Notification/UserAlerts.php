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
use OCA\IntrusionDetection\WasThisYou\Questions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUserManager;
use OCP\Notification\IManager as INotificationManager;

/**
 * Tells the affected user about a detection (concept section 11.1): a
 * notification and an email, both built by {@see UserMessages}, linking only
 * to the user's own security settings. The email is queued
 * ({@see MailQueue}) and sent by {@see self::sendMail()} from a background
 * job, never in the request that caused the detection.
 *
 * Aggregated per check and user per interval (an hour; a day for an
 * account under attack): later hits of a detection the user was told about
 * only raise a counter. A different detection in the same interval that
 * waits for a "Was this you?" answer (from another address, or after an
 * answer) is told on its own, so it can be answered, up to
 * MAX_DETECTIONS_PER_INTERVAL detections.
 *
 * Users without an email address are a normal case. They get the
 * notification, the event is shown once more at their next login from a
 * known device ({@see LoginNotices}), and for severe detections the
 * administrators are told that the user could only be reached inside
 * Nextcloud. Further ways to reach such users belong in
 * {@see self::unreachable()}. Users not emailed because the hour's cap
 * across all accounts was reached see the event at their next login too.
 */
class UserAlerts {
	public const SUBJECT = 'user_detection';
	public const OBJECT_TYPE = 'user_detection';
	/** Counter key prefix; "@user:<uid>" fits the counter column */
	public const KEY_PREFIX = '@user:';
	/** Counter key prefix of the further detections told in an interval */
	public const FURTHER_KEY_PREFIX = '@userd:';
	/** At most this many different detections of one check are told per user and interval */
	public const MAX_DETECTIONS_PER_INTERVAL = 3;
	public const DEFAULT_INTERVAL = 3600;
	/** @var array<string, int> checks that tell their users less often */
	public const INTERVALS = [AccountUnderAttack::ID => 86400, StepUpRefusedClient::ID => 86400, StepUpUnconfirmed::ID => 86400];
	/** Users without email: the administrators are told from this severity on */
	public const UNREACHABLE_MIN_SEVERITY = Severity::High;

	public const BELL_SENT = 'sent';
	public const BELL_AGGREGATED = 'aggregated';
	public const EMAIL_SENT = 'sent';
	public const EMAIL_QUEUED = 'queued';
	/** Not emailed: the hour's cap of emails to users was reached */
	public const EMAIL_LIMITED = 'limited';
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
		private readonly LoginNotices $loginNotices,
		private readonly Questions $questions,
		private readonly MailQueue $queue,
	) {
	}

	/**
	 * The counter keys of an account, for deleting them with it.
	 *
	 * @return list<string>
	 */
	public static function counterKeys(string $uid): array {
		return [self::KEY_PREFIX . $uid, self::FURTHER_KEY_PREFIX . $uid];
	}

	/**
	 * @param bool $isNew whether the detection was created by this hit, rather than merged into
	 * @return ?array{bell: string, email: string, admins: int} null when the detection's account does not exist (any more), or is not told about it
	 */
	public function notify(Detection $detection, bool $isNew = true): ?array {
		$uid = $detection->getUid();
		$user = $uid === null ? null : $this->userManager->get($uid);
		if ($uid === null || $user === null || !$user->isEnabled() || !$this->messages->tellsUser($detection)) {
			return null;
		}
		$now = $this->timeFactory->getTime();
		$interval = self::INTERVALS[$detection->getCheckId()] ?? self::DEFAULT_INTERVAL;
		$bucket = intdiv($now, $interval);
		[, $first] = $this->alerts->hit($detection->getCheckId(), self::KEY_PREFIX . $uid, $bucket, $detection->getId(), $now);
		if (!$first && !$this->tellsFurther($detection, $isNew, $uid, $bucket, $now)) {
			return ['bell' => self::BELL_AGGREGATED, 'email' => self::EMAIL_AGGREGATED, 'admins' => 0];
		}

		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser($uid)
			->setDateTime(new \DateTime('@' . $now))
			->setObject(self::OBJECT_TYPE, (string)$detection->getId())
			->setSubject(self::SUBJECT, ['detection' => $detection->getId()]);
		$this->notifications->notify($notification);

		if ((string)$user->getEMailAddress() === '') {
			return ['bell' => self::BELL_SENT, 'email' => self::EMAIL_NO_ADDRESS, 'admins' => $this->unreachable($detection, $uid, self::EMAIL_NO_ADDRESS)];
		}
		if (!$this->queue->user($detection->getId(), $uid)) {
			$this->loginNotices->remember($uid, $detection->getCreatedAt());
			return ['bell' => self::BELL_SENT, 'email' => self::EMAIL_LIMITED, 'admins' => 0];
		}
		return ['bell' => self::BELL_SENT, 'email' => self::EMAIL_QUEUED, 'admins' => 0];
	}

	/**
	 * Send the queued email about a detection to its account. When it cannot
	 * be sent, the user is treated as reachable inside Nextcloud only.
	 */
	public function sendMail(Detection $detection, string $uid): void {
		$user = $this->userManager->get($uid);
		if ($user === null || !$user->isEnabled() || $detection->getUid() !== $uid) {
			return;
		}
		if ((string)$user->getEMailAddress() === '') {
			$this->unreachable($detection, $uid, self::EMAIL_NO_ADDRESS);
		} elseif (!$this->mails->send($user, $this->messages->mail($detection, $user))) {
			$this->unreachable($detection, $uid, self::EMAIL_FAILED);
		}
	}

	/**
	 * Whether a detection that is not the first of its interval is told on
	 * its own: only a new one that waits for its answer, up to the limit.
	 */
	private function tellsFurther(Detection $detection, bool $isNew, string $uid, int $bucket, int $now): bool {
		if (!$isNew || !$this->questions->isOpen($detection)) {
			return false;
		}
		[$counterId] = $this->alerts->hit($detection->getCheckId(), self::FURTHER_KEY_PREFIX . $uid, $bucket, $detection->getId(), $now);
		$hits = $this->alerts->find($counterId)['hits'] ?? PHP_INT_MAX;
		return $hits < self::MAX_DETECTIONS_PER_INTERVAL;
	}

	/**
	 * The user could only be told inside Nextcloud: they see it again at
	 * their next login from a known device. For severe detections the
	 * administrators are told, so that they can reach out.
	 *
	 * @return int how many administrators were notified
	 */
	private function unreachable(Detection $detection, string $uid, string $email): int {
		$this->loginNotices->remember($uid, $detection->getCreatedAt());
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
