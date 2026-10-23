<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Notification\IManager as INotificationManager;

/**
 * "Send a test alert to me": one bell notification and one email to the
 * administrator who asks, both marked as a test, through the same channels
 * as real alerts. Nothing about a real detection is included.
 */
class TestAlert {
	public const SUBJECT = 'test_alert';
	public const OBJECT_TYPE = 'test';

	public const EMAIL_SENT = 'sent';
	public const EMAIL_NO_ADDRESS = 'no_address';
	public const EMAIL_NO_MAIL = 'no_mail';
	public const EMAIL_FAILED = 'failed';

	public function __construct(
		private readonly INotificationManager $notifications,
		private readonly Mails $mails,
		private readonly Prerequisites $prerequisites,
		private readonly IFactory $l10nFactory,
		private readonly AdminLinks $links,
		private readonly ITimeFactory $timeFactory,
		private readonly MailReach $reach,
	) {
	}

	/**
	 * @return array{bell: bool, email: self::EMAIL_*, address: ?string}
	 */
	public function send(IUser $user): array {
		$now = $this->timeFactory->getTime();
		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser($user->getUID())
			->setDateTime(new \DateTime('@' . $now))
			->setObject(self::OBJECT_TYPE, (string)$now)
			->setSubject(self::SUBJECT);
		$this->notifications->notify($notification);

		$address = (string)$user->getEMailAddress();
		if (!$this->reach->hasAddress($user)) {
			$email = self::EMAIL_NO_ADDRESS;
		} elseif (!$this->prerequisites->hasMail()) {
			$email = self::EMAIL_NO_MAIL;
		} else {
			$email = $this->mails->send($user, $this->mail($user)) ? self::EMAIL_SENT : self::EMAIL_FAILED;
		}
		return ['bell' => true, 'email' => $email, 'address' => $address === '' ? null : $address];
	}

	public function mail(IUser $user): MailContent {
		$language = $this->l10nFactory->getUserLanguage($user);
		$l = $this->l10nFactory->get(Application::APP_ID, $language);
		return new MailContent(
			templateId: 'intrusion_detection.testAlert',
			subject: $l->t('[Test] Intrusion detection: test alert'),
			heading: $l->t('This is a test alert'),
			paragraphs: [
				$l->t('You asked for a test alert on the intrusion detection admin page. Nothing has happened; no address was blocked.'),
				$l->t('Real alerts look like this one and reach you the same way: in the notifications of Nextcloud, and by email for detections of the severity you chose.'),
			],
			buttonText: $l->t('Open intrusion detection'),
			buttonUrl: $this->links->adminPage(),
			language: $language,
		);
	}
}
