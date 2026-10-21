<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AdminChange;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Notification\Notifier;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IGroup;
use OCP\IGroupManager;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Notification\IManager as INotificationManager;
use Psr\Log\LoggerInterface;

/**
 * Requests for the approval of a second administrator, and the rules for
 * deciding them, in one place for the admin page, the notification actions
 * and occ:
 *
 * - only a pending request that has not expired can be decided;
 * - the deciding account must be an enabled member of the admin group;
 * - neither the account the request is about nor the administrator who asked
 *   can approve it (the one who asked may withdraw it by rejecting);
 * - only one decision wins, also when two administrators decide at once.
 *
 * Approving adds the account to the group with a one-shot permit, so that
 * this one addition does not ask for approval again. Rejected and expired
 * requests change nothing; the one who asked is told.
 *
 * A login that nothing else could confirm (concept section 11.5) is a
 * request of the kind `login`, asked by the account itself: approving it
 * only marks it approved, and the waiting login continues. The account can
 * withdraw it, but never approve it. Every login gets its own request, so
 * that one approval never lets a second login of the same account through.
 */
class ApprovalService {
	/** Requests beyond this many pending ones are not stored, so a script cannot flood the table */
	public const MAX_PENDING = 100;
	/** Logins of one account beyond this many waiting ones are not stored */
	public const MAX_PENDING_LOGINS = 3;
	/** Decided requests are kept this long */
	public const RETENTION_DAYS = 90;

	public const VIA_WEB = 'web';
	public const VIA_OCC = 'occ';

	public const OBJECT_TYPE = 'approval';
	public const RESULT_OBJECT_TYPE = 'approval_result';

	public function __construct(
		private readonly ApprovalMapper $mapper,
		private readonly Approvers $approvers,
		private readonly GrantPermit $permit,
		private readonly IGroupManager $groupManager,
		private readonly IUserManager $userManager,
		private readonly Settings $settings,
		private readonly INotificationManager $notifications,
		private readonly IURLGenerator $urlGenerator,
		private readonly AuditLogger $audit,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * Ask for approval of an account joining a group. An open request for the
	 * same account and group is reused.
	 *
	 * @return ?Approval null when too many requests are pending already
	 */
	public function request(IUser $subject, IGroup $group, string $requester, ?string $ip): ?Approval {
		$now = $this->timeFactory->getTime();
		$existing = $this->mapper->findPending(Approval::KIND_ADMIN_GRANT, $subject->getUID(), $group->getGID());
		if ($existing !== null && $existing->getExpiresAt() > $now) {
			return $existing;
		}
		if ($this->mapper->countPending() >= self::MAX_PENDING) {
			$this->audit->log('request to add %s to %s by %s not stored: too many pending requests', [
				'subject' => $subject->getUID(),
				'group' => $group->getGID(),
				'requester' => $requester,
			]);
			return null;
		}

		$approval = new Approval();
		$approval->setKind(Approval::KIND_ADMIN_GRANT);
		$approval->setSubjectUid($subject->getUID());
		$approval->setRequestedBy($requester);
		$approval->setGroupId($group->getGID());
		$approval->setIp($ip);
		$approval->setStatus(Approval::STATUS_PENDING);
		$approval->setCreatedAt($now);
		$approval->setExpiresAt($now + $this->settings->getInt(GlobalSettings::ADMIN_CHANGE_APPROVAL_TTL));
		$approval = $this->mapper->insert($approval);

		$this->audit->log('approval requested: %s to join %s, asked by %s (request %s)', [
			'subject' => $subject->getUID(),
			'group' => $group->getGID(),
			'requester' => $requester,
			'approval' => $approval->getId(),
		]);
		$this->notifyApprovers($approval);
		if (ActorResolver::isPerson($requester)) {
			$this->notifyUser($requester, $approval, Notifier::SUBJECT_APPROVAL_PENDING, self::OBJECT_TYPE);
		}
		return $approval;
	}

	/**
	 * Ask the administrators to approve a login of the account.
	 *
	 * @return ?Approval null when nobody else could approve it, or too many requests are pending
	 */
	public function requestLogin(IUser $subject, ?string $ip, int $ttl, ?string $purpose = null): ?Approval {
		$now = $this->timeFactory->getTime();
		$uid = $subject->getUID();
		if ($this->approvers->except([$uid]) === []
			|| $this->mapper->countPending() >= self::MAX_PENDING
			|| $this->mapper->countPendingFor(Approval::KIND_LOGIN, $uid, $now) >= self::MAX_PENDING_LOGINS) {
			$this->audit->log('request to approve a login of %s not stored: nobody else can approve it, or too many requests are pending', ['subject' => $uid]);
			return null;
		}
		$approval = new Approval();
		$approval->setKind(Approval::KIND_LOGIN);
		$approval->setSubjectUid($uid);
		$approval->setRequestedBy($uid);
		$approval->setGroupId($purpose);
		$approval->setIp($ip);
		$approval->setStatus(Approval::STATUS_PENDING);
		$approval->setCreatedAt($now);
		$approval->setExpiresAt($now + $ttl);
		$approval = $this->mapper->insert($approval);
		$this->audit->log('approval requested: login of %s from %s (request %s)', [
			'subject' => $uid,
			'ip' => $ip ?? '-',
			'approval' => $approval->getId(),
		]);
		$this->notifyApprovers($approval);
		return $approval;
	}

	/**
	 * The account withdraws its own waiting login.
	 *
	 * @return bool whether a pending request was withdrawn
	 */
	public function withdrawLogin(int $id, string $uid): bool {
		try {
			$approval = $this->mapper->findById($id);
		} catch (DoesNotExistException) {
			return false;
		}
		if ($approval->getKind() !== Approval::KIND_LOGIN || $approval->getSubjectUid() !== $uid
			|| !$this->mapper->decide($id, Approval::STATUS_REJECTED, $uid, $this->timeFactory->getTime())) {
			return false;
		}
		$this->audit->log('approval %s withdrawn by %s: the login was given up', ['approval' => $id, 'subject' => $uid]);
		$this->finish($approval);
		return true;
	}

	/**
	 * @throws ApprovalException
	 */
	public function find(int $id): Approval {
		try {
			return $this->mapper->findById($id);
		} catch (DoesNotExistException) {
			throw new ApprovalException(ApprovalException::NOT_FOUND);
		}
	}

	/**
	 * @param ?string $kind only requests of this kind
	 * @return list<Approval> newest first
	 */
	public function list(bool $pendingOnly, int $limit = 200, ?string $kind = null): array {
		return $this->mapper->findList($pendingOnly, $limit, $kind);
	}

	/**
	 * Approve a request and carry it out.
	 *
	 * @param string $decider the uid of the approving administrator
	 * @throws ApprovalException
	 */
	public function approve(int $id, string $decider, string $via): Approval {
		$approval = $this->decidable($id);
		$this->assertMayDecide($approval, $decider);
		if ($decider === $approval->getRequestedBy()) {
			throw new ApprovalException(ApprovalException::REQUESTER);
		}
		if ($approval->getKind() === Approval::KIND_LOGIN) {
			return $this->approveLogin($approval, $decider, $via);
		}
		$user = $this->userManager->get($approval->getSubjectUid()) ?? throw new ApprovalException(ApprovalException::SUBJECT_MISSING);
		$group = $this->groupManager->get((string)$approval->getGroupId()) ?? throw new ApprovalException(ApprovalException::GROUP_MISSING);

		$now = $this->timeFactory->getTime();
		if (!$this->mapper->decide((int)$approval->getId(), Approval::STATUS_APPROVED, $decider, $now)) {
			throw new ApprovalException(ApprovalException::NOT_PENDING);
		}
		$this->audit->log('approval %s approved by %s via %s: %s joins %s, asked by %s', [
			'approval' => $approval->getId(),
			'decider' => $decider,
			'via' => $via,
			'subject' => $approval->getSubjectUid(),
			'group' => $approval->getGroupId(),
			'requester' => $approval->getRequestedBy(),
		]);

		$this->permit->allow($user->getUID(), $group->getGID(), [
			'approval' => (int)$approval->getId(),
			'requested_by' => $approval->getRequestedBy(),
			'approved_by' => $decider,
		]);
		try {
			$group->addUser($user);
		} finally {
			$this->permit->revoke($user->getUID(), $group->getGID());
		}

		return $this->finish($approval);
	}

	/**
	 * @throws ApprovalException
	 */
	private function approveLogin(Approval $approval, string $decider, string $via): Approval {
		if (!$this->mapper->decide((int)$approval->getId(), Approval::STATUS_APPROVED, $decider, $this->timeFactory->getTime())) {
			throw new ApprovalException(ApprovalException::NOT_PENDING);
		}
		$this->audit->log('approval %s approved by %s via %s: login of %s from %s', [
			'approval' => $approval->getId(),
			'decider' => $decider,
			'via' => $via,
			'subject' => $approval->getSubjectUid(),
			'ip' => $approval->getIp() ?? '-',
		]);
		return $this->finish($approval);
	}

	/**
	 * Reject a request. Any member of the admin group may, also the one who
	 * asked (to withdraw it), but not the account it is about.
	 *
	 * @param ?string $decider the uid of the rejecting administrator; null for occ without --as
	 * @throws ApprovalException
	 */
	public function reject(int $id, ?string $decider, string $via): Approval {
		$approval = $this->decidable($id);
		if ($decider !== null) {
			$this->assertMayDecide($approval, $decider);
		}
		if (!$this->mapper->decide((int)$approval->getId(), Approval::STATUS_REJECTED, $decider ?? ActorResolver::OCC, $this->timeFactory->getTime())) {
			throw new ApprovalException(ApprovalException::NOT_PENDING);
		}
		if ($approval->getKind() === Approval::KIND_LOGIN) {
			$this->audit->log('approval %s rejected by %s via %s: login of %s from %s', [
				'approval' => $approval->getId(),
				'decider' => $decider ?? ActorResolver::OCC,
				'via' => $via,
				'subject' => $approval->getSubjectUid(),
				'ip' => $approval->getIp() ?? '-',
			]);
		} else {
			$this->audit->log('approval %s rejected by %s via %s: %s does not join %s, asked by %s', [
				'approval' => $approval->getId(),
				'decider' => $decider ?? ActorResolver::OCC,
				'via' => $via,
				'subject' => $approval->getSubjectUid(),
				'group' => $approval->getGroupId(),
				'requester' => $approval->getRequestedBy(),
			]);
		}
		return $this->finish($approval);
	}

	/**
	 * End every pending request whose time ran out, and tell the ones who
	 * asked. Also removes decided requests past retention.
	 *
	 * @return int how many expired now
	 */
	public function expireDue(): int {
		$now = $this->timeFactory->getTime();
		$expired = 0;
		foreach ($this->mapper->findExpired($now) as $approval) {
			if ($this->expire($approval, $now)) {
				$expired++;
			}
		}
		$this->mapper->deleteDecidedBefore($now - self::RETENTION_DAYS * 86400);
		return $expired;
	}

	/**
	 * A pending request that can still be decided.
	 *
	 * @throws ApprovalException
	 */
	private function decidable(int $id): Approval {
		$approval = $this->find($id);
		if (!$approval->isPending()) {
			throw new ApprovalException(ApprovalException::NOT_PENDING);
		}
		$now = $this->timeFactory->getTime();
		if ($approval->getExpiresAt() <= $now) {
			$this->expire($approval, $now);
			throw new ApprovalException(ApprovalException::EXPIRED);
		}
		return $approval;
	}

	/**
	 * @throws ApprovalException
	 */
	private function assertMayDecide(Approval $approval, string $decider): void {
		if ($decider === $approval->getSubjectUid()) {
			throw new ApprovalException(ApprovalException::SUBJECT);
		}
		if (!$this->approvers->isApprover($decider)) {
			throw new ApprovalException(ApprovalException::NOT_ADMIN);
		}
	}

	private function expire(Approval $approval, int $now): bool {
		if (!$this->mapper->decide((int)$approval->getId(), Approval::STATUS_EXPIRED, null, $now)) {
			return false;
		}
		if ($approval->getKind() === Approval::KIND_LOGIN) {
			$this->audit->log('approval %s expired: login of %s from %s', [
				'approval' => $approval->getId(),
				'subject' => $approval->getSubjectUid(),
				'ip' => $approval->getIp() ?? '-',
			]);
		} else {
			$this->audit->log('approval %s expired: %s did not join %s, asked by %s', [
				'approval' => $approval->getId(),
				'subject' => $approval->getSubjectUid(),
				'group' => $approval->getGroupId(),
				'requester' => $approval->getRequestedBy(),
			]);
		}
		$this->finish($approval);
		return true;
	}

	/**
	 * After a decision: remove the open notifications and tell the one who asked.
	 */
	private function finish(Approval $approval): Approval {
		$approval = $this->find((int)$approval->getId());
		try {
			$notification = $this->notifications->createNotification();
			$notification->setApp(Application::APP_ID)
				->setObject(self::OBJECT_TYPE, (string)$approval->getId());
			$this->notifications->markProcessed($notification);
			// The account of a login request sees the decision on its waiting page.
			if ($approval->getKind() !== Approval::KIND_LOGIN && ActorResolver::isPerson($approval->getRequestedBy()) && $approval->getRequestedBy() !== $approval->getDecidedBy()) {
				$this->notifyUser($approval->getRequestedBy(), $approval, Notifier::SUBJECT_APPROVAL_DECIDED, self::RESULT_OBJECT_TYPE);
			}
		} catch (\Throwable $e) {
			// The decision stands even if a notification cannot be sent.
			$this->logger->error('Intrusion detection could not send the approval notifications', ['exception' => $e]);
		}
		return $approval;
	}

	/**
	 * Ask every administrator who may decide: all members of the admin group
	 * except the one who asked and the account the request is about.
	 */
	private function notifyApprovers(Approval $approval): void {
		$now = $this->timeFactory->getTime();
		foreach ($this->approvers->except([$approval->getRequestedBy(), $approval->getSubjectUid()]) as $user) {
			$notification = $this->notifications->createNotification();
			$notification->setApp(Application::APP_ID)
				->setUser($user->getUID())
				->setDateTime(new \DateTime('@' . $now))
				->setObject(self::OBJECT_TYPE, (string)$approval->getId())
				->setSubject(Notifier::SUBJECT_APPROVAL_REQUESTED, ['approval' => (int)$approval->getId()]);
			foreach ([Notifier::ACTION_APPROVE => 'approve', Notifier::ACTION_REJECT => 'reject'] as $label => $route) {
				$action = $notification->createAction();
				$action->setLabel($label)
					->setLink($this->urlGenerator->linkToOCSRouteAbsolute(Application::APP_ID . '.Approval.' . $route, ['id' => (int)$approval->getId()]), 'POST')
					->setPrimary($label === Notifier::ACTION_APPROVE);
				$notification->addAction($action);
			}
			$this->notifications->notify($notification);
		}
	}

	private function notifyUser(string $uid, Approval $approval, string $subject, string $objectType): void {
		$notification = $this->notifications->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser($uid)
			->setDateTime(new \DateTime('@' . $this->timeFactory->getTime()))
			->setObject($objectType, (string)$approval->getId())
			->setSubject($subject, ['approval' => (int)$approval->getId()]);
		$this->notifications->notify($notification);
	}
}
