<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Share\ShareLinks;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Notification\IManager as INotificationManager;
use OCP\Share\IShare;

/**
 * Tells the people who manage a share that its password is being guessed:
 * a notification with "Open share settings" and "Disable link", and an
 * email to those who have an address.
 *
 * Called once per detection; repeated wrong passwords for the same share
 * merge into that detection, and the notification shows its current count.
 * The notification and its actions carry only the detection id.
 */
class ShareOwnerAlerts {
	public const SUBJECT = 'share_attacked';
	public const OBJECT_TYPE = 'share_alert';
	public const ACTION_OPEN = 'open';
	public const ACTION_DISABLE = 'disable';

	public function __construct(
		private readonly ShareLinks $links,
		private readonly ShareBruteforce $check,
		private readonly IUserManager $userManager,
		private readonly INotificationManager $notifications,
		private readonly Mails $mails,
		private readonly IFactory $l10nFactory,
		private readonly IURLGenerator $urlGenerator,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return array{recipients: list<string>, emails: int}
	 */
	public function alert(Detection $detection, IShare $share): array {
		$now = $this->timeFactory->getTime();
		$recipients = [];
		$emails = 0;
		foreach ($this->links->managers($share) as $uid) {
			$user = $this->userManager->get($uid);
			if ($user === null || !$user->isEnabled()) {
				continue;
			}
			$this->notify($user, $detection, $share, $now);
			$recipients[] = $uid;
			if ($this->mails->send($user, $this->mailFor($detection, $share, $user))) {
				$emails++;
			}
		}
		return ['recipients' => $recipients, 'emails' => $emails];
	}

	/**
	 * Remove the notification about a detection for everyone, e.g. after the
	 * link was disabled.
	 */
	public function dismiss(int $detectionId): void {
		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setObject(self::OBJECT_TYPE, (string)$detectionId);
		$this->notifications->markProcessed($notification);
	}

	public function mailFor(Detection $detection, IShare $share, IUser $user): MailContent {
		$language = $this->l10nFactory->getUserLanguage($user);
		$l = $this->l10nFactory->get(Application::APP_ID, $language);
		$notice = $this->check->userNotice($detection, $l);
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
			language: $language,
		);
	}

	private function notify(IUser $user, Detection $detection, IShare $share, int $now): void {
		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser($user->getUID())
			->setDateTime(new \DateTime('@' . $now))
			->setObject(self::OBJECT_TYPE, (string)$detection->getId())
			->setSubject(self::SUBJECT, ['detection' => $detection->getId()]);
		$open = $notification->createAction();
		$open->setLabel(self::ACTION_OPEN)
			->setLink($this->links->settingsLink($share), 'WEB')
			->setPrimary(true);
		$notification->addAction($open);
		if ($this->links->isLink($share)) {
			$disable = $notification->createAction();
			$disable->setLabel(self::ACTION_DISABLE)
				->setLink($this->urlGenerator->linkToOCSRouteAbsolute(Application::APP_ID . '.ShareAlert.disable', ['detectionId' => $detection->getId()]), 'POST');
			$notification->addAction($disable);
		}
		$this->notifications->notify($notification);
	}
}
