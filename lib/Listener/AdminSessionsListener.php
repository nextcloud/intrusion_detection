<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\AdminChange\DelegatedGroups;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Response\Tokens;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\Group\Events\UserAddedEvent;
use OCP\IGroupManager;
use Psr\Log\LoggerInterface;

/**
 * While "administrators from trusted networks only" is on, an account that
 * becomes an administrator (the admin group, or a group with delegated
 * administration settings) loses its browser sessions: they were let in
 * as an ordinary account's, so nothing checked their network. Its next
 * login is held to the rule. App passwords are not affected by the rule
 * and stay. Runs after the approval of new administrators, and does
 * nothing when that took the addition back.
 *
 * @template-implements IEventListener<UserAddedEvent>
 */
class AdminSessionsListener implements IEventListener {
	public const PRIORITY = Application::ADMIN_SESSIONS_PRIORITY;

	public function __construct(
		private readonly AppSettings $settings,
		private readonly IGroupManager $groupManager,
		private readonly DelegatedGroups $delegated,
		private readonly Tokens $tokens,
		private readonly AuditLogger $audit,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof UserAddedEvent) {
			return;
		}
		try {
			if (!$this->settings->isEnabled() || !$this->settings->adminTrustedNetworksOnly()) {
				return;
			}
			$gid = $event->getGroup()->getGID();
			$uid = $event->getUser()->getUID();
			if (($gid !== Approvers::ADMIN_GROUP && $this->delegated->of($gid) === null) || !$this->groupManager->isInGroup($uid, $gid)) {
				return;
			}
			$ended = $this->tokens->invalidateSessionsExcept($uid, -1);
			if ($ended > 0) {
				$this->audit->log('%s browser sessions of %s ended: the account became an administrator', ['count' => $ended, 'uid' => $uid]);
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not end the sessions of a new administrator', ['exception' => $e]);
		}
	}
}
