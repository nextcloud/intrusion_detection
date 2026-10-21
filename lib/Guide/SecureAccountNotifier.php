<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Guide;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\IURLGenerator;
use OCP\L10N\IFactory;
use OCP\Notification\AlreadyProcessedException;
use OCP\Notification\INotification;
use OCP\Notification\INotifier;
use OCP\Notification\UnknownNotificationException;

/**
 * Renders the notification that invites a user to the "Secure my account"
 * checklist. It disappears once the checklist is finished or dismissed.
 */
class SecureAccountNotifier implements INotifier {
	public const PAGE_ROUTE = Application::APP_ID . '.SecureAccount.page';

	public function __construct(
		private readonly IFactory $l10nFactory,
		private readonly SecureAccountGuide $guide,
		private readonly IURLGenerator $urlGenerator,
		private readonly AdminLinks $links,
	) {
	}

	#[\Override]
	public function getID(): string {
		return Application::APP_ID . '_secure_account';
	}

	#[\Override]
	public function getName(): string {
		return $this->l10nFactory->get(Application::APP_ID)->t('Secure my account');
	}

	#[\Override]
	public function prepare(INotification $notification, string $languageCode): INotification {
		if ($notification->getApp() !== Application::APP_ID || $notification->getSubject() !== SecureAccountGuide::NOTIFICATION_SUBJECT) {
			throw new UnknownNotificationException();
		}
		$state = $this->guide->state($notification->getUser());
		if ($state === null || $state['closed'] !== null) {
			throw new AlreadyProcessedException();
		}
		$l = $this->l10nFactory->get(Application::APP_ID, $languageCode);
		$message = match ($state['reason']) {
			SecureAccountGuide::REASON_REENABLED => $l->t('Your administrator enabled your account again after it was locked. A short checklist helps you make sure nobody else can get in.'),
			SecureAccountGuide::REASON_DENIED => $l->t('You said that something on your account was not you. A short checklist helps you make sure nobody else can get in.'),
			default => $l->t('Nextcloud noticed that someone else may have had your password. A short checklist helps you make sure nobody else can get in.'),
		};
		$notification->setIcon($this->links->icon())
			->setParsedSubject($l->t('Secure your account'))
			->setParsedMessage($message)
			->setLink($this->urlGenerator->linkToRouteAbsolute(self::PAGE_ROUTE));
		return $notification;
	}
}
