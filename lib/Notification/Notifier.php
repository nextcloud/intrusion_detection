<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Notification\Db\AlertMapper;
use OCA\IntrusionDetection\WasThisYou\Questions;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\IL10N;
use OCP\IURLGenerator;
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
 * counter of an aggregated alert is always current. Alerts and notices to
 * the administrators are shown only to readers who would get them now
 * ({@see AdminRecipients::includes()}); for anyone else, such as a former
 * administrator, they are processed.
 */
class Notifier implements INotifier {
	public const SUBJECT_LEARNING_ENDS = 'learning_ends';
	public const SUBJECT_PROTECTION_STARTED = 'protection_started';
	/** To the administrators who may decide on a request for approval */
	public const SUBJECT_APPROVAL_REQUESTED = 'approval_requested';
	/** To the administrator who asked, while the request waits */
	public const SUBJECT_APPROVAL_PENDING = 'approval_pending';
	/** To the administrator who asked, once the request was decided or expired */
	public const SUBJECT_APPROVAL_DECIDED = 'approval_decided';
	/** To a user who has app passwords or devices they have not used for 90 days */
	public const SUBJECT_STALE_REMINDER = 'stale_credentials';
	/** To a user whose unused app passwords or devices were removed */
	public const SUBJECT_STALE_REMOVED = 'stale_credentials_removed';

	public const ACTION_PROTECT = 'protect';
	public const ACTION_EXTEND = 'extend';
	/** Opens the admin page, where an administrator decides on a request for approval */
	public const ACTION_REVIEW = 'review';
	/** The action of requests stored with separate approve and reject actions; shown as the review action */
	public const ACTION_APPROVE = 'approve';
	/** "Was this you?" on the user's own notification */
	public const ACTION_DENY = 'deny';
	public const ACTION_CONFIRM = 'confirm';

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
		private readonly ApprovalMapper $approvals,
		private readonly DateFormatter $dates,
		private readonly Questions $questions,
		private readonly IURLGenerator $urlGenerator,
		private readonly LearningService $learning,
		private readonly AdminChange $adminChange,
		private readonly AdminRecipients $recipients,
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
		$notification->setIcon($this->links->icon());
		// Prepared also for push and email, outside the recipient's session.
		$user = $this->userManager->get($notification->getUser());
		if ($user === null) {
			return $this->prepareSubject($notification, $this->l10nFactory->get(Application::APP_ID, $languageCode), $languageCode);
		}
		$l = $this->userMessages->l10nFor($user, $languageCode);
		return $this->userMessages->asReader($user, $l, fn (): INotification => $this->prepareSubject($notification, $l, $languageCode));
	}

	private function prepareSubject(INotification $notification, IL10N $l, string $languageCode): INotification {
		return match ($notification->getSubject()) {
			AdminAlerts::SUBJECT => $this->prepareDetection($notification, $l),
			self::SUBJECT_LEARNING_ENDS => $this->prepareLearningEnds($notification, $l),
			self::SUBJECT_PROTECTION_STARTED => $this->prepareProtectionStarted($notification, $l),
			UserAlerts::SUBJECT => $this->prepareUserDetection($notification, $languageCode),
			AdminNotices::SUBJECT_USER_UNREACHABLE => $this->prepareUserUnreachable($notification, $l, $languageCode),
			AdminNotices::SUBJECT_PASSWORD_EXTERNAL => $this->preparePasswordExternal($notification, $l),
			self::SUBJECT_APPROVAL_REQUESTED, self::SUBJECT_APPROVAL_PENDING, self::SUBJECT_APPROVAL_DECIDED => $this->prepareApproval($notification, $l),
			TestAlert::SUBJECT => $this->prepareTestAlert($notification, $l),
			self::SUBJECT_STALE_REMINDER => $this->prepareStaleReminder($notification, $l),
			self::SUBJECT_STALE_REMOVED => $this->prepareStaleRemoved($notification, $l),
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
		$this->requireRecipient($notification, AdminAlerts::reachesAdminGroup($detection));
		$hits = max(1, $alert['hits'] ?? 1);
		$name = $this->adminAlerts->checkName($detection->getCheckId(), $l);
		$headline = $this->adminAlerts->headline($detection, $l);

		$ip = $detection->getIp();
		$uid = $detection->getUid();
		$richParams = ['check' => ['type' => 'highlight', 'id' => $detection->getCheckId(), 'name' => $name]];
		if ($this->adminAlerts->customHeadline($detection, $l) !== null) {
			// The check's own headline is plain text; the rich subject would not match it.
			$richSubject = '';
			$richParams = [];
		} elseif ($ip !== null) {
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

		$notification->setParsedSubject($headline);
		if ($richSubject !== '') {
			$notification->setRichSubject($richSubject, $richParams);
		}
		$notification->setParsedMessage(implode(' ', $message))
			->setLink($this->links->detection($detection->getId()));
		return $notification;
	}

	private function prepareLearningEnds(INotification $notification, IL10N $l): INotification {
		if (!$this->learning->isEndingNoticePending()) {
			// Learning mode was started, extended or ended since.
			throw new AlreadyProcessedException();
		}
		$params = $notification->getSubjectParameters();
		$detections = (int)($params['detections'] ?? 0);
		$blocks = (int)($params['blocks'] ?? 0);
		$days = max(1, (int)($params['days'] ?? 7));
		$message = [
			$l->t('Intrusion detection is still learning and sends its alerts.'),
			$l->t('Checks set to Protect only record what they would block; earlier blocks, blocks you add by hand, a user\'s "No, it was not me", decoys and reserved names still block.'),
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
				// Both change protection and need the password, which the notification cannot ask: the admin page decides.
				$action->setParsedLabel($label)->setLink($this->links->adminPage(), 'WEB');
				$notification->addParsedAction($action);
			}
		}
		return $notification;
	}

	private function prepareApproval(INotification $notification, IL10N $l): INotification {
		try {
			$approval = $this->approvals->findById((int)($notification->getSubjectParameters()['approval'] ?? 0));
		} catch (DoesNotExistException) {
			throw new AlreadyProcessedException();
		}
		$subjectId = $notification->getSubject();
		if ($subjectId !== self::SUBJECT_APPROVAL_DECIDED && !$approval->isPending()) {
			// Decided in the meantime: nothing is left to do.
			throw new AlreadyProcessedException();
		}
		$account = $approval->getSubjectUid();
		$requester = AdminChange::actorName($approval->getRequestedBy(), $l);
		$expires = $this->dates->dateTime($approval->getExpiresAt());
		if ($approval->getKind() === Approval::KIND_LOGIN) {
			return $this->prepareLoginApproval($notification, $approval, $l, $expires);
		}
		if ($approval->getKind() === Approval::KIND_SETTINGS) {
			return $this->prepareSettingsApproval($notification, $approval, $l, $expires, $requester);
		}

		$group = (string)$approval->getGroupId();
		$delegated = $group !== AdminRecipients::ADMIN_GROUP;
		if ($subjectId === self::SUBJECT_APPROVAL_REQUESTED) {
			$notification->setParsedSubject($delegated
				? $l->t('%1$s asks to add %2$s to the group "%3$s", which has administration rights', [$requester, $account, $group])
				: $l->t('%1$s asks to make %2$s an administrator', [$requester, $account]))
				->setParsedMessage(implode(' ', [
					$l->t('A second administrator must approve new administrators, so %s was not added yet.', [$account]),
					$l->t('Approve only if you know about this change. If you did not expect it, reject it and check the account of the one who asked: it may have been taken over.'),
					$l->t('The request expires at %s. Approving needs your password, so you decide on the admin page.', [$expires]),
				]));
			$this->addReviewAction($notification, $approval, $l->t('Review the request'));
		} elseif ($subjectId === self::SUBJECT_APPROVAL_PENDING) {
			$notification->setParsedSubject($delegated
				? $l->t('%1$s is not in the group "%2$s" yet', [$account, $group])
				: $l->t('%s is not an administrator yet', [$account]))
				->setParsedMessage($delegated
					? $l->t('A second administrator must approve new administrators, so %1$s was taken out of the group "%2$s" again. The other administrators were asked to approve; the request expires at %3$s.', [$account, $group, $expires])
					: $l->t('A second administrator must approve new administrators, so %1$s was taken out of the admin group again. The other administrators were asked to approve; the request expires at %2$s.', [$account, $expires]));
		} else {
			$decider = AdminChange::actorName((string)$approval->getDecidedBy(), $l);
			[$subject, $message] = match ($approval->getStatus()) {
				Approval::STATUS_APPROVED => [
					$delegated ? $l->t('%1$s is now in the group "%2$s"', [$account, $group]) : $l->t('%s is now an administrator', [$account]),
					$l->t('%s approved your request.', [$decider]),
				],
				Approval::STATUS_REJECTED => [
					$delegated ? $l->t('Your request to add %1$s to the group "%2$s" was rejected', [$account, $group]) : $l->t('Your request to make %s an administrator was rejected', [$account]),
					$l->t('%s rejected it. Nothing was changed.', [$decider]),
				],
				default => [
					$delegated ? $l->t('Your request to add %1$s to the group "%2$s" expired', [$account, $group]) : $l->t('Your request to make %s an administrator expired', [$account]),
					$l->t('No other administrator approved it in time. Nothing was changed. Ask again if it is still needed.'),
				],
			};
			$notification->setParsedSubject($subject)->setParsedMessage($message);
		}
		$notification->setLink($this->links->approval((int)$approval->getId()));
		return $notification;
	}

	/**
	 * A settings change that would switch the four-eyes approval off, held
	 * back until a second administrator approves it.
	 */
	private function prepareSettingsApproval(INotification $notification, Approval $approval, IL10N $l, string $expires, string $requester): INotification {
		$change = $this->adminChange->heldChange($approval->heldChange(), $l);
		$subjectId = $notification->getSubject();
		if ($subjectId === self::SUBJECT_APPROVAL_REQUESTED) {
			$notification->setParsedSubject($l->t('%s asks for a change that needs your approval', [$requester]))
				->setParsedMessage(implode(' ', [
					$change,
					$l->t('While a second administrator must approve new administrators, one administrator alone cannot switch that off.'),
					$l->t('Approve only if you know about this change. If you did not expect it, reject it and check the account of the one who asked: it may have been taken over.'),
					$l->t('The request expires at %s. Approving needs your password, so you decide on the admin page.', [$expires]),
				]));
			$this->addReviewAction($notification, $approval, $l->t('Review the request'));
		} elseif ($subjectId === self::SUBJECT_APPROVAL_PENDING) {
			$notification->setParsedSubject($l->t('Your change waits for approval'))
				->setParsedMessage(implode(' ', [
					$change,
					$l->t('It is made once another administrator approves it; the request expires at %s.', [$expires]),
				]));
		} else {
			$decider = AdminChange::actorName((string)$approval->getDecidedBy(), $l);
			[$subject, $message] = match ($approval->getStatus()) {
				Approval::STATUS_APPROVED => [$l->t('Your change was approved'), $l->t('%s approved it, and it was made.', [$decider])],
				Approval::STATUS_REJECTED => [$l->t('Your change was rejected'), $l->t('%s rejected it. Nothing was changed.', [$decider])],
				default => [$l->t('Your change expired'), $l->t('No other administrator approved it in time. Nothing was changed.')],
			};
			$notification->setParsedSubject($subject)->setParsedMessage(implode(' ', [$message, $change]));
		}
		$notification->setLink($this->links->approval((int)$approval->getId()));
		return $notification;
	}

	/**
	 * A login that waits for an administrator. Only the administrators who
	 * may decide are asked; the account sees the decision on its waiting page.
	 */
	private function prepareLoginApproval(INotification $notification, Approval $approval, IL10N $l, string $expires): INotification {
		if ($notification->getSubject() !== self::SUBJECT_APPROVAL_REQUESTED) {
			throw new AlreadyProcessedException();
		}
		$account = $approval->getSubjectUid();
		$address = $approval->getIp() ?? $l->t('an unknown address');
		$notification->setParsedSubject($l->t('Approve the login of %s?', [$account]))
			->setRichSubject($l->t('Approve the login of {user}?'), ['user' => ['type' => 'user', 'id' => $account, 'name' => $account]])
			->setParsedMessage(implode(' ', [
				$l->t('%1$s logged in from the address %2$s with the correct password. The login needs extra confirmation, and the account has no other way to give it.', [$account, $address]),
				$l->t('Approve only if you know it is really %s, for example because they asked you. If you did not expect it, reject it: someone else may know the password.', [$account]),
				$l->t('The request expires at %s. Approving needs your password, so you decide on the admin page.', [$expires]),
			]))
			->setLink($this->links->decide($approval));
		$this->addReviewAction($notification, $approval, $l->t('Review the login'));
		return $notification;
	}

	/**
	 * Approving needs the password, which no notification can ask, neither
	 * on the web nor in the clients: one button opens the admin page, where
	 * the administrator decides. The notifications app shows every web link
	 * as a primary button, so a Reject link would look like Approve.
	 */
	private function addReviewAction(INotification $notification, Approval $approval, string $label): void {
		foreach ($notification->getActions() as $action) {
			if (in_array($action->getLabel(), [self::ACTION_REVIEW, self::ACTION_APPROVE], true)) {
				$action->setParsedLabel($label)
					->setLink($this->links->decide($approval), 'WEB')
					->setPrimary(true);
				$notification->addParsedAction($action);
				return;
			}
		}
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
	 *
	 * While the detection waits for an answer to "Was this you?", the
	 * notification offers both answers. "No" carries only the detection id;
	 * the endpoint checks that it is the user's own. "Yes" needs the
	 * password, so it opens the security page to answer there.
	 */
	private function prepareUserDetection(INotification $notification, string $languageCode): INotification {
		$detection = $this->detectionOf($notification);
		$user = $detection->getUid() === null ? null : $this->userManager->get($detection->getUid());
		if ($user === null || $user->getUID() !== $notification->getUser() || !$this->userMessages->tellsUser($detection)) {
			throw new AlreadyProcessedException();
		}
		$message = $this->userMessages->build($detection, $user, $languageCode);
		$notification->setParsedSubject($message->subject)
			->setParsedMessage($message->text())
			->setLink($this->userLinks->securityPage());
		if ($notification->getParsedActions() === [] && $this->questions->isOpen($detection)) {
			$l = $this->l10nFactory->get(Application::APP_ID, $languageCode);
			$deny = $notification->createAction();
			$deny->setLabel(self::ACTION_DENY)
				->setParsedLabel($l->t('No, it was not me'))
				->setLink($this->urlGenerator->linkToOCSRouteAbsolute(Application::APP_ID . '.PersonalApi.deny', ['id' => $detection->getId()]), 'POST')
				->setPrimary(true);
			$notification->addParsedAction($deny);
			// "Yes" needs the password first, which the notification cannot ask: it opens the security page.
			$confirm = $notification->createAction();
			$confirm->setLabel(self::ACTION_CONFIRM)
				->setParsedLabel($l->t('Yes, it was me'))
				->setLink($this->userLinks->securityPage(), 'WEB')
				->setPrimary(false);
			$notification->addParsedAction($confirm);
		}
		return $notification;
	}

	private function prepareUserUnreachable(INotification $notification, IL10N $l, string $languageCode): INotification {
		$this->requireRecipient($notification, false);
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
		$this->requireRecipient($notification, false);
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

	/**
	 * @throws AlreadyProcessedException when the reader no longer gets the administrators' alerts
	 */
	private function requireRecipient(INotification $notification, bool $withAdminGroup): void {
		$reader = $this->userManager->get($notification->getUser());
		if ($reader === null || !$this->recipients->includes($reader, $withAdminGroup)) {
			throw new AlreadyProcessedException();
		}
	}

	private function detectionOf(INotification $notification): Detection {
		try {
			return $this->detections->findById((int)($notification->getSubjectParameters()['detection'] ?? 0));
		} catch (DoesNotExistException) {
			throw new AlreadyProcessedException();
		}
	}

	/**
	 * "You have 3 app passwords you haven't used for 3 months", from the
	 * counts the reminder carries.
	 */
	private function prepareStaleReminder(INotification $notification, IL10N $l): INotification {
		$params = $notification->getSubjectParameters();
		$apps = max(0, (int)($params['appPasswords'] ?? 0));
		$sessions = max(0, (int)($params['sessions'] ?? 0));
		$subject = match (true) {
			$sessions === 0 => $l->n('You have %n app password you haven\'t used for 3 months', 'You have %n app passwords you haven\'t used for 3 months', $apps),
			$apps === 0 => $l->n('You are still logged in on %n browser you haven\'t used for 3 months', 'You are still logged in on %n browsers you haven\'t used for 3 months', $sessions),
			default => $l->n('You have %n app password or device you haven\'t used for 3 months', 'You have %n app passwords and devices you haven\'t used for 3 months', $apps + $sessions),
		};
		$notification->setParsedSubject($subject)
			->setParsedMessage($l->t('If someone else had one of them, it would be easy to miss. Remove the ones you no longer need in your security settings.'))
			->setLink($this->userLinks->securityPage());
		return $notification;
	}

	/**
	 * What the daily job removed, with the names the credentials had.
	 */
	private function prepareStaleRemoved(INotification $notification, IL10N $l): INotification {
		$params = $notification->getSubjectParameters();
		$apps = max(0, (int)($params['appPasswords'] ?? 0));
		$sessions = max(0, (int)($params['sessions'] ?? 0));
		$days = (string)max(0, (int)($params['days'] ?? 0));
		$subject = match (true) {
			$sessions === 0 => $l->n('Removed %n app password you had not used for %s days', 'Removed %n app passwords you had not used for %s days', $apps, [$days]),
			$apps === 0 => $l->n('Logged out %n browser you had not used for %s days', 'Logged out %n browsers you had not used for %s days', $sessions, [$days]),
			default => $l->n('Removed %n app password or device you had not used for %s days', 'Removed %n app passwords and devices you had not used for %s days', $apps + $sessions, [$days]),
		};
		$names = array_values(array_filter(array_map(static fn (mixed $name): string => is_string($name) ? $name : '', (array)($params['names'] ?? [])), static fn (string $name): bool => $name !== ''));
		$message = $l->t('An app that still needs access asks you to log in again.');
		if ($names !== []) {
			$message = $l->t('Removed: %s.', [implode(', ', $names)]) . ' ' . $message;
		}
		$notification->setParsedSubject($subject)
			->setParsedMessage($message)
			->setLink($this->userLinks->securityPage());
		return $notification;
	}

	private function prepareTestAlert(INotification $notification, IL10N $l): INotification {
		$notification->setParsedSubject($l->t('Test alert from intrusion detection'))
			->setParsedMessage($l->t('This is a test you asked for. Nothing has happened. Real alerts reach you here in the same way.'))
			->setLink($this->links->adminPage() . '#settings-notifications');
		return $notification;
	}
}
