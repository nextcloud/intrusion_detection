<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\IL10N;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Notification\AlreadyProcessedException;
use OCP\Notification\INotification;
use OCP\Notification\INotifier;
use OCP\Notification\UnknownNotificationException;

/**
 * Renders the app's notifications in the reader's language.
 *
 * Notifications carry only identifiers; everything shown is built here from
 * the stored detection, so the texts follow the reader's language and the
 * counter of an aggregated alert is always current.
 */
class Notifier implements INotifier {
	public const SUBJECT_LEARNING_ENDS = 'learning_ends';
	public const SUBJECT_PROTECTION_STARTED = 'protection_started';

	public const ACTION_PROTECT = 'protect';
	public const ACTION_EXTEND = 'extend';

	public function __construct(
		private readonly IFactory $l10nFactory,
		private readonly AlertMapper $alerts,
		private readonly DetectionMapper $detections,
		private readonly AdminAlerts $adminAlerts,
		private readonly NarrativeBuilder $narratives,
		private readonly AdminLinks $links,
		private readonly UserMessages $userMessages,
		private readonly UserLinks $userLinks,
		private readonly IUserManager $userManager,
	) {
	}

	#[\Override]
	public function getID(): string {
		return Application::APP_ID;
	}

	#[\Override]
	public function getName(): string {
		return $this->l10nFactory->get(Application::APP_ID)->t('Intrusion detection');
	}

	#[\Override]
	public function prepare(INotification $notification, string $languageCode): INotification {
		if ($notification->getApp() !== Application::APP_ID) {
			throw new UnknownNotificationException();
		}
		$l = $this->l10nFactory->get(Application::APP_ID, $languageCode);
		$notification->setIcon($this->links->icon());
		return match ($notification->getSubject()) {
			AdminAlerts::SUBJECT => $this->prepareDetection($notification, $l),
			self::SUBJECT_LEARNING_ENDS => $this->prepareLearningEnds($notification, $l),
			self::SUBJECT_PROTECTION_STARTED => $this->prepareProtectionStarted($notification, $l),
			UserAlerts::SUBJECT => $this->prepareUserDetection($notification, $languageCode),
			AdminNotices::SUBJECT_USER_UNREACHABLE => $this->prepareUserUnreachable($notification, $l, $languageCode),
			AdminNotices::SUBJECT_PASSWORD_EXTERNAL => $this->preparePasswordExternal($notification, $l),
			default => throw new UnknownNotificationException(),
		};
	}

	private function prepareDetection(INotification $notification, IL10N $l): INotification {
		$params = $notification->getSubjectParameters();
		$alert = $this->alerts->find((int)($params['alert'] ?? 0));
		$detectionId = $alert['detection_id'] ?? (int)($params['detection'] ?? 0);
		try {
			$detection = $this->detections->findById($detectionId);
		} catch (DoesNotExistException) {
			// Removed by retention or by an administrator: nothing left to show.
			throw new AlreadyProcessedException();
		}
		$hits = max(1, $alert['hits'] ?? 1);
		$name = $this->adminAlerts->checkName($detection->getCheckId(), $l);
		$headline = $this->adminAlerts->headline($detection, $l);

		$ip = $detection->getIp();
		$uid = $detection->getUid();
		$richParams = ['check' => ['type' => 'highlight', 'id' => $detection->getCheckId(), 'name' => $name]];
		if ($ip !== null) {
			$richSubject = $l->t('{check} from {address}');
			$richParams['address'] = ['type' => 'highlight', 'id' => $ip, 'name' => $ip];
		} elseif ($uid !== null) {
			$richSubject = $l->t('{check}: account {user}');
			$richParams['user'] = ['type' => 'user', 'id' => $uid, 'name' => $uid];
		} else {
			$richSubject = '{check}';
		}

		$narrative = $this->narratives->build($detection, $l);
		$message = $narrative->happened;
		if ($hits > 1) {
			$message[] = $l->n('This happened %n time within the hour.', 'This happened %n times within the hour.', $hits);
		}
		$message[] = implode(' ', $narrative->done);

		$notification->setParsedSubject($headline)
			->setRichSubject($richSubject, $richParams)
			->setParsedMessage(implode(' ', $message))
			->setLink($this->links->detection($detection->getId()));
		return $notification;
	}

	private function prepareLearningEnds(INotification $notification, IL10N $l): INotification {
		$params = $notification->getSubjectParameters();
		$detections = (int)($params['detections'] ?? 0);
		$blocks = (int)($params['blocks'] ?? 0);
		$days = max(1, (int)($params['days'] ?? 7));
		$message = [
			$l->t('Intrusion detection is still learning: it watches, but does not act.'),
			$detections === 0
				? $l->n('In the last %n day it found nothing it would have acted on.', 'In the last %n days it found nothing it would have acted on.', $days)
				: $l->n('In the last %n day it would have acted on %1$s detections and blocked %2$s addresses.', 'In the last %n days it would have acted on %1$s detections and blocked %2$s addresses.', $days, [(string)$detections, (string)$blocks]),
			$l->t('If you do nothing, it starts protecting automatically when the learning period ends.'),
		];
		$notification->setParsedSubject($l->t('The learning period of intrusion detection ends tomorrow'))
			->setParsedMessage(implode(' ', $message))
			->setLink($this->links->adminPage());

		foreach ($notification->getActions() as $action) {
			$label = match ($action->getLabel()) {
				self::ACTION_PROTECT => $l->t('Start protecting now'),
				self::ACTION_EXTEND => $l->t('Observe 7 more days'),
				default => null,
			};
			if ($label !== null) {
				$action->setParsedLabel($label);
				$notification->addParsedAction($action);
			}
		}
		return $notification;
	}

	private function prepareProtectionStarted(INotification $notification, IL10N $l): INotification {
		$notification->setParsedSubject($l->t('Intrusion detection is now protecting this server'))
			->setParsedMessage($l->t('The learning period is over. Checks set to Protect now act on what they find. You can start learning mode again on the admin page at any time.'))
			->setLink($this->links->adminPage());
		return $notification;
	}

	/**
	 * What the affected user is told. Only the notification's own recipient
	 * sees it, and only while the detection is still theirs.
	 */
	private function prepareUserDetection(INotification $notification, string $languageCode): INotification {
		$detection = $this->detectionOf($notification);
		$user = $detection->getUid() === null ? null : $this->userManager->get($detection->getUid());
		if ($user === null || $user->getUID() !== $notification->getUser()) {
			throw new AlreadyProcessedException();
		}
		$message = $this->userMessages->build($detection, $user, $languageCode);
		$notification->setParsedSubject($message->subject)
			->setParsedMessage($message->text())
			->setLink($this->userLinks->securityPage());
		return $notification;
	}

	private function prepareUserUnreachable(INotification $notification, IL10N $l, string $languageCode): INotification {
		$params = $notification->getSubjectParameters();
		$detection = $this->detectionOf($notification);
		$uid = (string)($params['uid'] ?? '');
		$user = $this->userManager->get($uid);
		if ($user === null || $detection->getUid() !== $uid) {
			throw new AlreadyProcessedException();
		}
		$told = $this->userMessages->build($detection, $user, $languageCode)->subject;
		$message = ($params['reason'] ?? null) === AdminNotices::REASON_MAIL_FAILED
			? $l->t('The email to %1$s could not be sent, so they could only be told inside Nextcloud: %2$s', [$uid, $told])
			: $l->t('%1$s has no email address, so they could only be told inside Nextcloud: %2$s', [$uid, $told]);
		$notification->setParsedSubject($l->t('%s could only be told inside Nextcloud', [$uid]))
			->setRichSubject($l->t('{user} could only be told inside Nextcloud'), ['user' => ['type' => 'user', 'id' => $uid, 'name' => $uid]])
			->setParsedMessage($message . ' ' . $l->t('If it matters, reach out to them another way.'))
			->setLink($this->links->detection($detection->getId()));
		return $notification;
	}

	private function preparePasswordExternal(INotification $notification, IL10N $l): INotification {
		$params = $notification->getSubjectParameters();
		$uid = (string)($params['uid'] ?? '');
		$user = $this->userManager->get($uid);
		if ($user === null) {
			throw new AlreadyProcessedException();
		}
		$detectionId = (int)($params['detection'] ?? 0);
		$notification->setParsedSubject($l->t('Reset the password of %s in the external directory', [$uid]))
			->setRichSubject($l->t('Reset the password of {user} in the external directory'), ['user' => ['type' => 'user', 'id' => $uid, 'name' => $uid]])
			->setParsedMessage($l->t('Intrusion detection wanted %1$s to choose a new password, but their password is managed outside Nextcloud (%2$s), so Nextcloud cannot ask for a new one. Reset the password in that directory, or ask the user to change it there.', [$uid, $user->getBackendClassName()]))
			->setLink($detectionId > 0 ? $this->links->detection($detectionId) : $this->links->adminPage());
		return $notification;
	}

	private function detectionOf(INotification $notification): Detection {
		try {
			return $this->detections->findById((int)($notification->getSubjectParameters()['detection'] ?? 0));
		} catch (DoesNotExistException) {
			throw new AlreadyProcessedException();
		}
	}
}
