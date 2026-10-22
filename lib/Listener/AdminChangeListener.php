<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\AdminGrantGate;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\AdminChange\ConfigWatch;
use OCA\IntrusionDetection\AdminChange\DelegatedGroups;
use OCA\IntrusionDetection\AdminChange\GrantPermit;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChangeDetector;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Event\SettingChangedEvent;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCP\App\Events\AppDisableEvent;
use OCP\App\Events\AppEnableEvent;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\Group\Events\SubAdminAddedEvent;
use OCP\Group\Events\UserAddedEvent;
use OCP\Group\Events\UserRemovedEvent;
use OCP\IGroup;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\User\Events\UserCreatedEvent;
use Psr\Log\LoggerInterface;

/**
 * Reports administration changes as they happen (concept section 10.15):
 *
 * - accounts added to or removed from the admin group, or a group with
 *   delegated administration settings;
 * - group administrators appointed;
 * - accounts created by an administrator or occ;
 * - apps switched on or off;
 * - this app's own settings changed through the app, except changes of the
 *   learning period that do not start it ({@see \OCA\IntrusionDetection\Learning\LearningService}).
 *
 * With four-eyes approval on, an account added to the admin group from the
 * web interface or the provisioning API is taken out again at once and a
 * request for approval is created; see {@see AdminGrantGate}. This listener
 * is registered with a low priority, so the other listeners of the addition
 * have finished before it is taken back, and the removal's listeners clean
 * up after them.
 *
 * Fails open: an error is logged and never breaks the change itself.
 *
 * @template-implements IEventListener<Event>
 */
class AdminChangeListener implements IEventListener {
	/** Listeners with a higher priority run first */
	public const PRIORITY = Application::ADMIN_CHANGE_PRIORITY;

	/**
	 * Removals reported in this request, by uid and group. Deleting an
	 * account sends UserRemovedEvent twice per group (from the group and
	 * from the account), which must be one detection.
	 *
	 * @var array<string, true>
	 */
	private array $reportedRemovals = [];

	public function __construct(
		private readonly CheckSettings $settings,
		private readonly AdminChangeDetector $detector,
		private readonly AdminGrantGate $gate,
		private readonly ApprovalService $approvals,
		private readonly GrantPermit $permit,
		private readonly DelegatedGroups $delegated,
		private readonly ConfigWatch $watch,
		private readonly ActorResolver $actors,
		private readonly RemoteAddressResolver $addresses,
		private readonly IGroupManager $groupManager,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		try {
			match (true) {
				$event instanceof UserAddedEvent => $this->userAdded($event->getGroup(), $event->getUser()),
				$event instanceof UserRemovedEvent => $this->userRemoved($event->getGroup(), $event->getUser()),
				$event instanceof SubAdminAddedEvent => $this->subAdminAdded($event->getGroup(), $event->getUser()),
				$event instanceof UserCreatedEvent => $this->userCreated($event->getUser()),
				$event instanceof AppEnableEvent => $this->appEnabled($event->getAppId(), $event->getGroupIds()),
				$event instanceof AppDisableEvent => $this->appDisabled($event->getAppId()),
				$event instanceof SettingChangedEvent => $this->settingChanged($event),
				default => null,
			};
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not handle an administration change', ['exception' => $e]);
		}
	}

	private function userAdded(IGroup $group, IUser $user): void {
		$gid = $group->getGID();
		unset($this->reportedRemovals[$user->getUID() . "\0" . $gid]);
		$delegated = $gid === Approvers::ADMIN_GROUP ? null : $this->delegated->of($gid);
		if ($gid !== Approvers::ADMIN_GROUP && $delegated === null) {
			return;
		}
		$decision = $this->gate->decide($group, $user);
		$actor = $this->actors->actor();

		if ($decision === AdminGrantGate::NEEDS_APPROVAL) {
			$this->holdForApproval($group, $user, $actor);
			return;
		}
		if (!$this->runs()) {
			return;
		}
		$facts = ['group' => $gid];
		if ($delegated !== null) {
			$facts['delegated'] = $delegated;
		}
		if ($decision === AdminGrantGate::APPROVED) {
			$facts += $this->gate->permitFacts();
		} elseif ($decision !== AdminGrantGate::NOT_NEEDED) {
			$facts['exempt'] = $decision;
		}
		$this->detector->record(AdminChange::KIND_ADMIN_GRANTED, Severity::High, $actor, $user->getUID(), facts: $facts, alertKey: AdminChange::KIND_ADMIN_GRANTED . ':' . $gid);
	}

	/**
	 * Take the new member out again and ask a second administrator. A stored
	 * request is recorded without an alert: the approvers already have its
	 * notification with Approve and Reject, which goes away with the
	 * decision. Without a request (too many pending, or the revert failed)
	 * the administrators are alerted as usual.
	 */
	private function holdForApproval(IGroup $group, IUser $user, string $actor): void {
		$uid = $user->getUID();
		$gid = $group->getGID();
		$this->permit->beginRevert($uid, $gid);
		try {
			$group->removeUser($user);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not take {uid} out of {gid} again', ['uid' => $uid, 'gid' => $gid, 'exception' => $e]);
		} finally {
			$this->permit->endRevert($uid, $gid);
		}
		$reverted = !$group->inGroup($user);

		$facts = ['group' => $gid, 'reverted' => $reverted, 'revert_failed' => !$reverted];
		if ($reverted) {
			$approval = $this->approvals->request($user, $group, $actor, $this->addresses->current()?->ip);
			if ($approval !== null) {
				$facts['approval'] = (int)$approval->getId();
				$facts['expires_at'] = $approval->getExpiresAt();
			}
		}
		$this->detector->record(AdminChange::KIND_GRANT_REQUESTED, Severity::High, $actor, $uid, facts: $facts, alertKey: AdminChange::KIND_GRANT_REQUESTED . ':' . $gid);
	}

	private function userRemoved(IGroup $group, IUser $user): void {
		$gid = $group->getGID();
		if ($this->permit->isReverting($user->getUID(), $gid) || !$this->runs()) {
			return;
		}
		$delegated = $gid === Approvers::ADMIN_GROUP ? null : $this->delegated->of($gid);
		if ($gid !== Approvers::ADMIN_GROUP && $delegated === null) {
			return;
		}
		$removal = $user->getUID() . "\0" . $gid;
		if (isset($this->reportedRemovals[$removal])) {
			return;
		}
		$this->reportedRemovals[$removal] = true;
		$facts = ['group' => $gid];
		if ($delegated !== null) {
			$facts['delegated'] = $delegated;
		}
		$this->detector->record(AdminChange::KIND_ADMIN_REMOVED, Severity::Low, $this->actors->actor(), $user->getUID(), facts: $facts, alertKey: AdminChange::KIND_ADMIN_REMOVED . ':' . $gid);
	}

	private function subAdminAdded(IGroup $group, IUser $user): void {
		if (!$this->runs()) {
			return;
		}
		$this->detector->record(AdminChange::KIND_SUBADMIN_GRANTED, Severity::Medium, $this->actors->actor(), $user->getUID(), facts: ['group' => $group->getGID()], alertKey: AdminChange::KIND_SUBADMIN_GRANTED);
	}

	/**
	 * Only accounts created by an administrator (or occ) are reported; people
	 * registering themselves, or accounts a user directory brings, are not.
	 * The event's password is never read.
	 */
	private function userCreated(IUser $user): void {
		if (!$this->runs()) {
			return;
		}
		$actor = $this->actors->actor();
		$byAdmin = $actor === ActorResolver::OCC
			|| (ActorResolver::isPerson($actor) && ($this->groupManager->isInGroup($actor, Approvers::ADMIN_GROUP) || $this->groupManager->isDelegatedAdmin($actor)));
		if (!$byAdmin) {
			return;
		}
		$this->detector->record(AdminChange::KIND_USER_CREATED, Severity::Low, $actor, $user->getUID(), facts: [], alertKey: AdminChange::KIND_USER_CREATED);
	}

	/**
	 * @param list<string> $groups
	 */
	private function appEnabled(string $appId, array $groups): void {
		if (!$this->runs()) {
			return;
		}
		$this->detector->record(AdminChange::KIND_APP_ENABLED, Severity::Medium, $this->actors->actor(), null, facts: ['app' => $appId, 'groups' => $groups], alertKey: AdminChange::KIND_APP_ENABLED);
	}

	private function appDisabled(string $appId): void {
		if (!$this->runs()) {
			return;
		}
		$severity = $appId === Application::APP_ID ? Severity::High : Severity::Medium;
		$this->detector->record(AdminChange::KIND_APP_DISABLED, $severity, $this->actors->actor(), null, facts: ['app' => $appId], alertKey: AdminChange::KIND_APP_DISABLED);
	}

	/**
	 * Judged by the check's mode before the change, so that switching the app
	 * or this check off is still reported. A change the app made on its own
	 * is no administration change.
	 */
	private function settingChanged(SettingChangedEvent $event): void {
		if (!$event->isReported()) {
			$this->watch->ownSettingRecorded($event->getKey(), $event->getNewValue());
			return;
		}
		$mode = $this->detector->modeBefore($event->getKey(), $event->getOldValue());
		$this->watch->ownSettingChanged($event->getKey(), $event->getOldValue(), $event->getNewValue(), $this->actors->actor(), $mode);
	}

	private function runs(): bool {
		return $this->settings->modeState(AdminChange::ID)->runs();
	}
}
