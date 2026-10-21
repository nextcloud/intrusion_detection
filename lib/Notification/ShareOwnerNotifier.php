<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCA\IntrusionDetection\Share\ShareLinks;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Notification\AlreadyProcessedException;
use OCP\Notification\INotification;
use OCP\Notification\INotifier;
use OCP\Notification\UnknownNotificationException;

/**
 * Renders the notifications for the people who manage a share whose
 * password is being guessed ({@see ShareOwnerAlerts}), from the stored
 * detection and the share as it is now.
 */
class ShareOwnerNotifier implements INotifier {
	public function __construct(
		private readonly IFactory $l10nFactory,
		private readonly DetectionMapper $detections,
		private readonly ShareBruteforce $check,
		private readonly ShareLinks $links,
		private readonly AdminLinks $adminLinks,
		private readonly UserMessages $messages,
		private readonly IUserManager $userManager,
	) {
	}

	#[\Override]
	public function getID(): string {
		return Application::APP_ID . '_shares';
	}

	#[\Override]
	public function getName(): string {
		return $this->l10nFactory->get(Application::APP_ID)->t('Share link attacks');
	}

	#[\Override]
	public function prepare(INotification $notification, string $languageCode): INotification {
		if ($notification->getApp() !== Application::APP_ID || $notification->getSubject() !== ShareOwnerAlerts::SUBJECT) {
			throw new UnknownNotificationException();
		}
		$l = $this->l10nFactory->get(Application::APP_ID, $languageCode);
		try {
			$detection = $this->detections->findById((int)($notification->getSubjectParameters()['detection'] ?? 0));
		} catch (DoesNotExistException) {
			throw new AlreadyProcessedException();
		}
		$share = $detection->getCheckId() === ShareBruteforce::ID ? $this->links->find($detection) : null;
		if ($share === null || !$this->links->canManage($share, $notification->getUser())) {
			// The link is gone, or no longer this person's to manage: nothing left to act on.
			throw new AlreadyProcessedException();
		}
		// Prepared also for push and email, outside the recipient's session.
		$user = $this->userManager->get($notification->getUser());
		if ($user !== null) {
			$l = $this->messages->l10nFor($user, $languageCode);
			$notice = $this->messages->asReader($user, $l, fn (): UserNotice => $this->check->userNotice($detection, $l));
		} else {
			$notice = $this->check->userNotice($detection, $l);
		}
		$notification->setIcon($this->adminLinks->icon())
			->setParsedSubject($notice->subject)
			->setParsedMessage(implode(' ', $notice->message))
			->setLink($this->links->settingsLink($share));

		foreach ($notification->getActions() as $action) {
			$label = match ($action->getLabel()) {
				ShareOwnerAlerts::ACTION_OPEN => $l->t('Open share settings'),
				ShareOwnerAlerts::ACTION_DISABLE => $l->t('Disable link'),
				default => null,
			};
			if ($label !== null) {
				$action->setParsedLabel($label);
				$notification->addParsedAction($action);
			}
		}
		return $notification;
	}
}
