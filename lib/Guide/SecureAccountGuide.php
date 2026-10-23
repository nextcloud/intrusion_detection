<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Guide;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\UserKeys;
use OCA\IntrusionDetection\Confirm\SecondFactors;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Notification\IManager as INotificationManager;
use Psr\Log\LoggerInterface;

/**
 * The guided "Secure my account" checklist (concept section 15.3).
 *
 * It starts after "No, it was not me", when an administrator enables an
 * account that was locked with the lock link, when a check that means
 * someone else had the password acted, or when the user starts it. Its
 * state is one small JSON value per account (user setting `secure_guide`):
 * when and why it started, the event it is about, when each step was done,
 * and when the guide was finished or dismissed.
 *
 * Steps are done in different ways:
 * - password: a new password was set after the guide started; when the
 *   password is managed outside Nextcloud, an administrator marks it;
 * - two_factor: the account has a second factor (checked live); skipped
 *   when no provider is available on the server;
 * - sessions, email, shares, files: the user confirms they checked them.
 */
class SecureAccountGuide {

	public const STEP_PASSWORD = 'password';
	public const STEP_SESSIONS = 'sessions';
	public const STEP_TWO_FACTOR = 'two_factor';
	public const STEP_EMAIL = 'email';
	public const STEP_SHARES = 'shares';
	public const STEP_FILES = 'files';
	public const STEPS = [self::STEP_PASSWORD, self::STEP_SESSIONS, self::STEP_TWO_FACTOR, self::STEP_EMAIL, self::STEP_SHARES, self::STEP_FILES];
	/** Steps the user marks as done themselves */
	public const USER_STEPS = [self::STEP_SESSIONS, self::STEP_EMAIL, self::STEP_SHARES, self::STEP_FILES];

	public const REASON_DENIED = 'denied';
	public const REASON_REENABLED = 'reenabled';
	public const REASON_DETECTION = 'detection';
	public const REASON_SELF = 'self';

	public const CLOSED_DONE = 'done';
	public const CLOSED_DISMISSED = 'dismissed';

	/** Changes and shares are looked at from this long before the event on */
	public const LOOK_BACK = 7 * 86400;

	public const NOTIFICATION_SUBJECT = 'secure_account';
	public const NOTIFICATION_OBJECT = 'secure_account';

	public function __construct(
		private readonly IUserConfig $userConfig,
		private readonly IUserManager $userManager,
		private readonly SecondFactors $secondFactors,
		private readonly INotificationManager $notifications,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * Start the guide, or keep the one that is open and remember the newer
	 * reason. Tells the user with a notification unless they started it.
	 *
	 * @param self::REASON_* $reason
	 * @param ?int $eventAt when the suspicious event happened; now if unknown
	 */
	public function start(string $uid, string $reason, ?string $detectionId = null, ?int $eventAt = null): void {
		$now = $this->timeFactory->getTime();
		$state = $this->state($uid);
		$wasOpen = $state !== null && $state['closed'] === null;
		if (!$wasOpen) {
			$state = ['v' => 1, 'started' => $now, 'event' => $eventAt ?? $now, 'reason' => $reason, 'detection' => $detectionId, 'done' => [], 'closed' => null, 'closedBy' => null];
		} else {
			$state['reason'] = $reason;
			$state['detection'] = $detectionId ?? $state['detection'];
			$state['event'] = min($state['event'], $eventAt ?? $now);
		}
		$this->save($uid, $state);
		if ($reason !== self::REASON_SELF) {
			$this->notify($uid, $now, $wasOpen);
		}
	}

	/**
	 * The stored state, or null when the guide was never started.
	 *
	 * @return ?array{v: int, started: int, event: int, reason: string, detection: ?string, done: array<string, int>, closed: ?int, closedBy: ?string}
	 */
	public function state(string $uid): ?array {
		$raw = $this->userConfig->getValueString($uid, Application::APP_ID, UserKeys::SECURE_GUIDE, '', true);
		$data = $raw === '' ? null : json_decode($raw, true);
		if (!is_array($data) || !is_int($data['started'] ?? null)) {
			return null;
		}
		$done = [];
		foreach (is_array($data['done'] ?? null) ? $data['done'] : [] as $step => $at) {
			if (in_array($step, self::STEPS, true) && is_int($at)) {
				$done[$step] = $at;
			}
		}
		return [
			'v' => 1,
			'started' => $data['started'],
			'event' => is_int($data['event'] ?? null) ? $data['event'] : $data['started'],
			'reason' => is_string($data['reason'] ?? null) ? $data['reason'] : self::REASON_SELF,
			'detection' => is_string($data['detection'] ?? null) ? $data['detection'] : null,
			'done' => $done,
			'closed' => is_int($data['closed'] ?? null) ? $data['closed'] : null,
			'closedBy' => is_string($data['closedBy'] ?? null) ? $data['closedBy'] : null,
		];
	}

	public function isOpen(string $uid): bool {
		$state = $this->state($uid);
		return $state !== null && $state['closed'] === null;
	}

	/**
	 * Mark a step of the open guide done. The endpoints decide who may mark
	 * which step: users the ones in USER_STEPS, administrators the password
	 * of an account whose password is managed elsewhere.
	 *
	 * @return bool whether the open guide has the step done now
	 */
	public function markDone(string $uid, string $step): bool {
		$state = $this->state($uid);
		if ($state === null || $state['closed'] !== null || !in_array($step, self::STEPS, true)) {
			return false;
		}
		$state['done'][$step] ??= $this->timeFactory->getTime();
		$this->save($uid, $this->closeIfComplete($uid, $state));
		return true;
	}

	/**
	 * A new password was set: the password step is done when the guide was
	 * open before.
	 */
	public function passwordChanged(string $uid): void {
		$state = $this->state($uid);
		if ($state !== null && $state['closed'] === null && !isset($state['done'][self::STEP_PASSWORD])) {
			$this->markDone($uid, self::STEP_PASSWORD);
		}
	}

	public function dismiss(string $uid): bool {
		$state = $this->state($uid);
		if ($state === null || $state['closed'] !== null) {
			return false;
		}
		$state['closed'] = $this->timeFactory->getTime();
		$state['closedBy'] = self::CLOSED_DISMISSED;
		$this->save($uid, $state);
		$this->markNotificationProcessed($uid);
		return true;
	}

	/**
	 * The guide as the pages show it.
	 *
	 * @return array{active: bool, startedAt: ?int, eventAt: ?int, reason: ?string, detectionId: ?string, closedAt: ?int, closedBy: ?string, done: int, total: int, steps: list<array{id: SecureAccountGuide::STEP_*, done: bool, doneAt: ?int, skipped: bool, managed: bool, userConfirms: bool}>}
	 */
	public function progress(IUser $user): array {
		$state = $this->state($user->getUID());
		$steps = [];
		$done = 0;
		$total = 0;
		foreach (self::STEPS as $step) {
			$skipped = $step === self::STEP_TWO_FACTOR && !$this->secondFactors->available($user);
			$doneAt = $state['done'][$step] ?? null;
			if ($step === self::STEP_TWO_FACTOR && $doneAt === null && !$skipped && $this->secondFactors->has($user)) {
				$doneAt = $state['started'] ?? 0;
			}
			$isDone = $doneAt !== null && !$skipped;
			$steps[] = [
				'id' => $step,
				'done' => $isDone,
				'doneAt' => $isDone ? $doneAt : null,
				'skipped' => $skipped,
				'managed' => $step === self::STEP_PASSWORD && !$user->canChangePassword(),
				'userConfirms' => in_array($step, self::USER_STEPS, true),
			];
			if (!$skipped) {
				$total++;
				$done += $isDone ? 1 : 0;
			}
		}
		return [
			'active' => $state !== null && $state['closed'] === null,
			'startedAt' => $state['started'] ?? null,
			'eventAt' => $state['event'] ?? null,
			'reason' => $state['reason'] ?? null,
			'detectionId' => $state['detection'] ?? null,
			'closedAt' => $state['closed'] ?? null,
			'closedBy' => $state['closedBy'] ?? null,
			'done' => $done,
			'total' => $total,
			'steps' => $steps,
		];
	}

	/**
	 * @param array{v: int, started: int, event: int, reason: string, detection: ?string, done: array<string, int>, closed: ?int, closedBy: ?string} $state
	 * @return array{v: int, started: int, event: int, reason: string, detection: ?string, done: array<string, int>, closed: ?int, closedBy: ?string}
	 */
	private function closeIfComplete(string $uid, array $state): array {
		$user = $this->userManager->get($uid);
		if ($user === null) {
			return $state;
		}
		$this->save($uid, $state);
		$progress = $this->progress($user);
		if ($progress['done'] === $progress['total']) {
			$state['closed'] = $this->timeFactory->getTime();
			$state['closedBy'] = self::CLOSED_DONE;
			$this->markNotificationProcessed($uid);
		}
		return $state;
	}

	/**
	 * @param array{v: int, started: int, event: int, reason: string, detection: ?string, done: array<string, int>, closed: ?int, closedBy: ?string} $state
	 */
	private function save(string $uid, array $state): void {
		$this->userConfig->setValueString($uid, Application::APP_ID, UserKeys::SECURE_GUIDE, json_encode($state, JSON_THROW_ON_ERROR), true);
	}

	/**
	 * @param bool $replace whether an earlier invitation may exist; it is replaced by this one
	 */
	private function notify(string $uid, int $now, bool $replace): void {
		try {
			if ($replace) {
				$this->markNotificationProcessed($uid);
			}
			$notification = $this->notifications->createNotification();
			$notification->setApp(Application::APP_ID)
				->setUser($uid)
				->setDateTime(new \DateTime('@' . $now))
				->setObject(self::NOTIFICATION_OBJECT, $uid)
				->setSubject(self::NOTIFICATION_SUBJECT);
			$this->notifications->notify($notification);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not tell {uid} about securing their account', ['uid' => $uid, 'exception' => $e]);
		}
	}

	private function markNotificationProcessed(string $uid): void {
		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser($uid)
			->setObject(self::NOTIFICATION_OBJECT, $uid);
		$this->notifications->markProcessed($notification);
	}
}
