<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm\Methods;

use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;

/**
 * An administrator approves the login (concept section 11.5, method 4),
 * when `step_up_admin_approval` is on. The login waits on the verify page,
 * which asks for the request's status every few seconds; the
 * administrators get a notification with Approve and Reject. The request
 * expires after `step_up_admin_approval_ttl`, and the login may wait that
 * long, but never longer than `step_up_session_ttl` and one approval's
 * time after the login. A login asks once: when its request was rejected
 * or has expired, the login ends.
 *
 * The rules of {@see ApprovalService} apply: the account never approves
 * its own login, and only an enabled member of the admin group decides. It
 * is offered only when such an administrator other than the account exists.
 */
class AdminApprovalMethod implements IConfirmationMethod {
	public const STATUS_NONE = 'none';
	public const STATUS_PENDING = 'pending';
	public const STATUS_APPROVED = 'approved';
	public const STATUS_REJECTED = 'rejected';
	public const STATUS_EXPIRED = 'expired';

	/** @var array<string, bool> whether someone else can approve, by uid, for this request */
	private array $approvable = [];

	public function __construct(
		private readonly ApprovalService $approvals,
		private readonly ApprovalMapper $mapper,
		private readonly Approvers $approvers,
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	#[\Override]
	public function id(): string {
		return self::ADMIN_APPROVAL;
	}

	#[\Override]
	public function isAvailable(IUser $user, StepUpPolicy $policy): bool {
		if (!$this->settings->getBool(GlobalSettings::STEP_UP_ADMIN_APPROVAL)) {
			return false;
		}
		$uid = $user->getUID();
		return $this->approvable[$uid] ??= $this->approvers->except([$uid]) !== [];
	}

	#[\Override]
	public function isAvailableInBrowser(IUser $user, StepUpPolicy $policy): bool {
		return $this->isAvailable($user, $policy);
	}

	/**
	 * Ask the administrators. The login may wait until the request expires,
	 * at most `step_up_session_ttl` and one approval's time after the login.
	 */
	#[\Override]
	public function begin(IUser $user, StepUpState $state): string {
		$ttl = $this->settings->getInt(GlobalSettings::STEP_UP_ADMIN_APPROVAL_TTL);
		$approval = $this->approvals->requestLogin($user, $state->ip, $ttl);
		if ($approval === null) {
			return self::UNAVAILABLE;
		}
		$state->approvalId = $approval->getId();
		$latest = $state->started + $this->settings->getInt(GlobalSettings::STEP_UP_SESSION_TTL) + $ttl;
		$state->deadline = min(max($state->deadline, $approval->getExpiresAt()), $latest);
		return self::PENDING;
	}

	/**
	 * Where the login's request stands. One primary-key read.
	 *
	 * @return self::STATUS_*
	 */
	public function status(IUser $user, StepUpState $state): string {
		$approval = $this->approval($user, $state);
		if ($approval === null) {
			return self::STATUS_NONE;
		}
		return match ($approval->getStatus()) {
			Approval::STATUS_APPROVED => $approval->getDecidedBy() !== null && $approval->getDecidedBy() !== $user->getUID() ? self::STATUS_APPROVED : self::STATUS_REJECTED,
			Approval::STATUS_REJECTED => self::STATUS_REJECTED,
			Approval::STATUS_PENDING => $approval->getExpiresAt() > $this->timeFactory->getTime() ? self::STATUS_PENDING : self::STATUS_EXPIRED,
			default => self::STATUS_EXPIRED,
		};
	}

	/**
	 * When the login's request expires, or null without one.
	 */
	public function expiresAt(IUser $user, StepUpState $state): ?int {
		return $this->approval($user, $state)?->getExpiresAt();
	}

	/**
	 * The user gives up waiting.
	 */
	public function withdraw(IUser $user, StepUpState $state): bool {
		return $state->approvalId !== null && $this->approvals->withdrawLogin($state->approvalId, $user->getUID());
	}

	private function approval(IUser $user, StepUpState $state): ?Approval {
		if ($state->approvalId === null) {
			return null;
		}
		try {
			$approval = $this->mapper->findById($state->approvalId);
		} catch (DoesNotExistException) {
			return null;
		}
		return $approval->getKind() === Approval::KIND_LOGIN && $approval->getSubjectUid() === $user->getUID() ? $approval : null;
	}
}
