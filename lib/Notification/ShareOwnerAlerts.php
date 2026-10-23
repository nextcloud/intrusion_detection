<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Share\ShareLinks;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Notification\IManager as INotificationManager;
use OCP\Share\IShare;

/**
 * Tells the people who manage a share that its password is being guessed:
 * a notification with "Open share settings" and "Disable link", and an
 * email to those who have an address.
 *
 * Called once per detection; repeated wrong passwords for the same share
 * merge into that detection, and the notification shows its current count.
 * The notification and its actions carry only the detection id. The email
 * is queued ({@see MailQueue}) and sent by {@see self::sendMail()} from a
 * background job, to the people who manage the share at that moment.
 */
class ShareOwnerAlerts {
	public const SUBJECT = 'share_attacked';
	public const OBJECT_TYPE = 'share_alert';
	public const ACTION_OPEN = 'open';
	public const ACTION_DISABLE = 'disable';

	public const EMAIL_QUEUED = 'queued';
	/** Not emailed: the hour's cap of emails to users was reached */
	public const EMAIL_LIMITED = 'limited';
	public const EMAIL_NO_ADDRESS = 'no_address';

	public function __construct(
		private readonly ShareLinks $links,
		private readonly IUserManager $userManager,
		private readonly INotificationManager $notifications,
		private readonly Mails $mails,
		private readonly UserMessages $messages,
		private readonly IURLGenerator $urlGenerator,
		private readonly ITimeFactory $timeFactory,
		private readonly MailQueue $queue,
		private readonly MailReach $reach,
	) {
	}

	/**
	 * @return array{recipients: list<string>, email: self::EMAIL_*}
	 */
	public function alert(Detection $detection, IShare $share): array {
		$now = $this->timeFactory->getTime();
		$recipients = [];
		$withAddress = false;
		foreach ($this->managers($share) as $user) {
			$this->notify($user, $detection, $share, $now);
			$recipients[] = $user->getUID();
			$withAddress = $withAddress || $this->reach->hasAddress($user);
		}
		$email = match (true) {
			!$withAddress => self::EMAIL_NO_ADDRESS,
			$this->queue->shareOwners((string)$detection->getId(), Severity::from($detection->getSeverity())) => self::EMAIL_QUEUED,
			default => self::EMAIL_LIMITED,
		};
		return ['recipients' => $recipients, 'email' => $email];
	}

	/**
	 * Send the queued email about a detection to the people who manage its share.
	 *
	 * @return int how many emails were handed to the mail server
	 */
	public function sendMail(Detection $detection): int {
		$share = $this->links->find($detection);
		if ($share === null) {
			return 0;
		}
		$sent = 0;
		foreach ($this->managers($share) as $user) {
			if ($this->mails->send($user, $this->mailFor($detection, $share, $user))) {
				$sent++;
			}
		}
		return $sent;
	}

	/**
	 * @return list<IUser> the enabled accounts that manage the share
	 */
	private function managers(IShare $share): array {
		$users = [];
		foreach ($this->links->managers($share) as $uid) {
			$user = $this->userManager->get($uid);
			if ($user !== null && $user->isEnabled()) {
				$users[] = $user;
			}
		}
		return $users;
	}

	/**
	 * Remove the notification about a detection for everyone, e.g. after the
	 * link was disabled.
	 */
	public function dismiss(string $detectionId): void {
		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setObject(self::OBJECT_TYPE, $detectionId);
		$this->notifications->markProcessed($notification);
	}

	public function mailFor(Detection $detection, IShare $share, IUser $user): MailContent {
		$l = $this->messages->l10nFor($user);
		return $this->messages->asReader($user, $l, function () use ($detection, $share, $l): MailContent {
			$notice = $this->messages->notice($detection, $l);
			$paragraphs = $notice->message;
			if ($this->links->isLink($share)) {
				$paragraphs[] = $l->t('You can change the password or turn the link off in the sharing settings of the file, or with "Disable link" in the notification inside Nextcloud.');
			}
			return new MailContent(
				templateId: 'intrusion_detection.shareAttacked',
				subject: $notice->subject,
				heading: $notice->subject,
				paragraphs: $paragraphs,
				buttonText: $l->t('Open share settings'),
				buttonUrl: $this->links->settingsLink($share),
				language: $l->getLanguageCode(),
			);
		});
	}

	private function notify(IUser $user, Detection $detection, IShare $share, int $now): void {
		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser($user->getUID())
			->setDateTime(new \DateTime('@' . $now))
			->setObject(self::OBJECT_TYPE, (string)$detection->getId())
			->setSubject(self::SUBJECT, ['detection' => (string)$detection->getId()]);
		$open = $notification->createAction();
		$open->setLabel(self::ACTION_OPEN)
			->setLink($this->links->settingsLink($share), 'WEB')
			->setPrimary(true);
		$notification->addAction($open);
		if ($this->links->isLink($share)) {
			$disable = $notification->createAction();
			$disable->setLabel(self::ACTION_DISABLE)
				->setLink($this->urlGenerator->linkToOCSRouteAbsolute(Application::APP_ID . '.ShareAlert.disable', ['detectionId' => (string)$detection->getId()]), 'POST');
			$notification->addAction($disable);
		}
		$this->notifications->notify($notification);
	}
}
