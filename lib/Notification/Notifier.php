<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AdminChange;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\Lockdown;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Sensitive\SensitiveRoutes;
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
 * counter of an aggregated alert is always current.
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

	public const ACTION_PROTECT = 'protect';
	public const ACTION_EXTEND = 'extend';
	public const ACTION_APPROVE = 'approve';
	public const ACTION_REJECT = 'reject';
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
			self::SUBJECT_APPROVAL_REQUESTED, self::SUBJECT_APPROVAL_PENDING, self::SUBJECT_APPROVAL_DECIDED => $this->prepareApproval($notification, $l),
			TestAlert::SUBJECT => $this->prepareTestAlert($notification, $l),
			LockdownNotices::SUBJECT_STARTED, LockdownNotices::SUBJECT_ENDED => $this->prepareLockdown($notification, $l),
			AdminNotices::SUBJECT_SENSITIVE_UNCONFIRMED => $this->prepareSensitiveUnconfirmed($notification, $l),
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

		if ($subjectId === self::SUBJECT_APPROVAL_REQUESTED) {
			$notification->setParsedSubject($l->t('%1$s asks to make %2$s an administrator', [$requester, $account]))
				->setParsedMessage(implode(' ', [
					$l->t('A second administrator must approve new administrators, so %s was not added yet.', [$account]),
					$l->t('Approve only if you know about this change. If you did not expect it, reject it and check the account of the one who asked: it may have been taken over.'),
					$l->t('The request expires at %s. Deciding needs your password.', [$expires]),
				]));
			foreach ($notification->getActions() as $action) {
				$label = match ($action->getLabel()) {
					self::ACTION_APPROVE => $l->t('Approve'),
					self::ACTION_REJECT => $l->t('Reject'),
					default => null,
				};
				if ($label !== null) {
					$action->setParsedLabel($label);
					$notification->addParsedAction($action);
				}
			}
		} elseif ($subjectId === self::SUBJECT_APPROVAL_PENDING) {
			$notification->setParsedSubject($l->t('%s is not an administrator yet', [$account]))
				->setParsedMessage($l->t('A second administrator must approve new administrators, so %1$s was taken out of the admin group again. The other administrators were asked to approve; the request expires at %2$s.', [$account, $expires]));
		} else {
			$decider = AdminChange::actorName((string)$approval->getDecidedBy(), $l);
			[$subject, $message] = match ($approval->getStatus()) {
				Approval::STATUS_APPROVED => [
					$l->t('%s is now an administrator', [$account]),
					$l->t('%s approved your request.', [$decider]),
				],
				Approval::STATUS_REJECTED => [
					$l->t('Your request to make %s an administrator was rejected', [$account]),
					$l->t('%s rejected it. Nothing was changed.', [$decider]),
				],
				default => [
					$l->t('Your request to make %s an administrator expired', [$account]),
					$l->t('No other administrator approved it in time. Nothing was changed. Ask again if it is still needed.'),
				],
			};
			$notification->setParsedSubject($subject)->setParsedMessage($message);
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
		if ($approval->isSensitiveAction()) {
			$notification->setParsedSubject($l->t('Approve a sensitive action of %s?', [$account]))
				->setRichSubject($l->t('Approve a sensitive action of {user}?'), ['user' => ['type' => 'user', 'id' => $account, 'name' => $account]])
				->setParsedMessage(implode(' ', [
					$l->t('%1$s wants to change something important from the address %2$s, such as an email address, a password or an app password. Their session needs a fresh confirmation for it, and the account has no other way to give it.', [$account, $address]),
					$l->t('Approve only if you know it is really %s, for example because they asked you. If you did not expect it, reject it: someone else may be using the account, and the session is ended.', [$account]),
					$l->t('The request expires at %s. Deciding needs your password.', [$expires]),
				]))
				->setLink($this->links->adminPage() . '#confirmation');
			return $this->loginApprovalActions($notification, $l);
		}
		$notification->setParsedSubject($l->t('Approve the login of %s?', [$account]))
			->setRichSubject($l->t('Approve the login of {user}?'), ['user' => ['type' => 'user', 'id' => $account, 'name' => $account]])
			->setParsedMessage(implode(' ', [
				$l->t('%1$s logged in from the address %2$s with the correct password. The login needs extra confirmation, and the account has no other way to give it.', [$account, $address]),
				$l->t('Approve only if you know it is really %s, for example because they asked you. If you did not expect it, reject it: someone else may know the password.', [$account]),
				$l->t('The request expires at %s. Deciding needs your password.', [$expires]),
			]))
			->setLink($this->links->adminPage() . '#confirmation');
		return $this->loginApprovalActions($notification, $l);
	}

	private function loginApprovalActions(INotification $notification, IL10N $l): INotification {
		foreach ($notification->getActions() as $action) {
			$label = match ($action->getLabel()) {
				self::ACTION_APPROVE => $l->t('Approve'),
				self::ACTION_REJECT => $l->t('Reject'),
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
	 *
	 * While the detection waits for an answer to "Was this you?", the
	 * notification offers both answers. They carry only the detection id;
	 * the endpoints check that it is the user's own.
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
		if ($notification->getParsedActions() === [] && $this->questions->isOpen($detection)) {
			$l = $this->l10nFactory->get(Application::APP_ID, $languageCode);
			foreach ([self::ACTION_DENY => ['deny', $l->t('No, it was not me'), true], self::ACTION_CONFIRM => ['confirm', $l->t('Yes, it was me'), false]] as $label => [$route, $text, $primary]) {
				$action = $notification->createAction();
				$action->setLabel($label)
					->setParsedLabel($text)
					->setLink($this->urlGenerator->linkToOCSRouteAbsolute(Application::APP_ID . '.PersonalApi.' . $route, ['id' => $detection->getId()]), 'POST')
					->setPrimary($primary);
				$notification->addParsedAction($action);
			}
		}
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

	private function prepareTestAlert(INotification $notification, IL10N $l): INotification {
		$notification->setParsedSubject($l->t('Test alert from intrusion detection'))
			->setParsedMessage($l->t('This is a test you asked for. Nothing has happened. Real alerts reach you here in the same way.'))
			->setLink($this->links->adminPage() . '#notifications');
		return $notification;
	}

	/**
	 * A lockdown started or ended. Rendered from the notification's own
	 * parameters, so it reads the same after the lockdown's history entry
	 * was deleted.
	 */
	private function prepareLockdown(INotification $notification, IL10N $l): INotification {
		$params = $notification->getSubjectParameters();
		$startedBy = (string)($params['startedBy'] ?? '');
		$reason = (string)($params['reason'] ?? '');
		$started = $startedBy === Lockdown::ACTOR_AUTOMATIC
			? $l->t('It was started automatically because many addresses are trying passwords at the same time.')
			: $l->t('It was started by %s.', [$startedBy === Lockdown::ACTOR_OCC ? $l->t('a command on the server') : $startedBy]);
		$message = [$started];
		if ($reason !== '') {
			$message[] = $l->t('Reason: "%s"', [$reason]);
		}
		if ($notification->getSubject() === LockdownNotices::SUBJECT_STARTED) {
			$until = $this->dates->dateTime((int)($params['until'] ?? 0));
			$message[] = $l->t('While it lasts, Nextcloud asks for extra confirmation and blocks new devices as set on the admin page. You can extend or end it there, or with occ intrusion:lockdown.');
			$notification->setParsedSubject($l->t('Lockdown until %s', [$until]));
		} else {
			$endedBy = (string)($params['endedBy'] ?? '');
			$message[] = $endedBy === Lockdown::ACTOR_AUTOMATIC
				? $l->t('It ended at its planned time.')
				: $l->t('It was ended early by %s.', [$endedBy === Lockdown::ACTOR_OCC ? $l->t('a command on the server') : $endedBy]);
			$notification->setParsedSubject($l->t('The lockdown has ended'));
		}
		$notification->setParsedMessage(implode(' ', $message))
			->setLink($this->links->adminPage());
		return $notification;
	}

	/**
	 * A sensitive action went ahead in a risky session without a
	 * confirmation, because the account had no way to give one.
	 */
	private function prepareSensitiveUnconfirmed(INotification $notification, IL10N $l): INotification {
		$params = $notification->getSubjectParameters();
		$uid = (string)($params['uid'] ?? '');
		if ($this->userManager->get($uid) === null) {
			throw new AlreadyProcessedException();
		}
		$what = SensitiveRoutes::groupLabel((string)($params['group'] ?? ''), $l);
		$notification->setParsedSubject($l->t('%s did a sensitive action without confirmation', [$uid]))
			->setRichSubject($l->t('{user} did a sensitive action without confirmation'), ['user' => ['type' => 'user', 'id' => $uid, 'name' => $uid]])
			->setParsedMessage(implode(' ', [
				$l->t('%1$s changed something in "%2$s" in a session that needs extra confirmation for that.', [$uid, $what]),
				$l->t('The account has neither a second factor nor an email address, and your settings allow such actions with a notice instead of refusing them.'),
				$l->t('If you did not expect it, check the account.'),
			]))
			->setLink($this->links->adminPage() . '#confirmation');
		return $notification;
	}
}
