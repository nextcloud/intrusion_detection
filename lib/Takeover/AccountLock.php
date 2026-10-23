<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Takeover;

use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\AccountLocked\AccountLocked;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Guide\SecureAccountGuide;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\Tokens;
use OCA\IntrusionDetection\Takeover\Db\SecurityChangeMapper;
use OCP\IUserManager;
use OCP\IUserSession;
use Psr\Log\LoggerInterface;

/**
 * What using a lock link does (concept section 11.15), and the way back.
 *
 * Locking ends every session and app password of the account, disables
 * it, records a critical detection (`account_locked`) and tells all
 * administrators. It never unlocks or changes anything else. The last
 * enabled administrator is not disabled, since only the command line could
 * enable it again: its sessions and app passwords end all the same, and
 * the detection says so.
 *
 * Only an administrator enables a locked account again. That starts the
 * "Secure my account" checklist for its owner and requires a new password
 * at the next login, since whoever took the account over may know it.
 */
class AccountLock {
	public const LOCKED = 'locked';
	/** The sessions ended, but the last enabled administrator stayed enabled */
	public const SESSIONS_ENDED = 'sessions_ended';

	public const REENABLED = 'reenabled';
	public const NOT_LOCKED = 'not_locked';
	public const NO_ACCOUNT = 'no_account';
	public const NOT_A_LOCK = 'not_a_lock';

	public function __construct(
		private readonly LockLinks $links,
		private readonly SecurityChangeMapper $changes,
		private readonly Tokens $tokens,
		private readonly ResponseEngine $engine,
		private readonly SecureAccountGuide $guide,
		private readonly PasswordChangeService $passwords,
		private readonly Approvers $approvers,
		private readonly IUserManager $userManager,
		private readonly IUserSession $userSession,
		private readonly RemoteAddressResolver $addresses,
		private readonly AuditLogger $audit,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * Lock the account of a lock link, once.
	 *
	 * @return LockLinks::VALID|LockLinks::USED|LockLinks::EXPIRED|LockLinks::INVALID|self::LOCKED|self::SESSIONS_ENDED what happened: LOCKED or SESSIONS_ENDED, or why not
	 */
	public function lock(int $linkId, #[\SensitiveParameter] string $token): string {
		[$state, $link] = $this->links->check($linkId, $token);
		if ($state !== LockLinks::VALID || $link === null) {
			return $state;
		}
		$user = $this->userManager->get($link['uid']);
		if ($user === null) {
			return LockLinks::INVALID;
		}
		$source = $this->addresses->current();
		if (!$this->links->use($linkId, $source?->ip)) {
			return LockLinks::USED;
		}
		$uid = $user->getUID();
		$lastAdmin = $this->approvers->isApprover($uid) && $this->approvers->except([$uid]) === [];

		$ended = $this->tokens->invalidateAll($uid);
		if ($this->userSession->getUser()?->getUID() === $uid) {
			$this->userSession->logout();
		}
		if ($lastAdmin) {
			$this->audit->log('sessions of %s ended with the lock link sent to %s; the account stays enabled as the last enabled administrator', ['uid' => $uid, 'sentTo' => $link['sent_to_hint']]);
		} else {
			$user->setEnabled(false);
			$this->audit->log('account %s locked with the lock link sent to %s', ['uid' => $uid, 'sentTo' => $link['sent_to_hint']]);
		}

		$change = $link['change_id'] === null ? null : $this->changes->find($link['change_id']);
		try {
			$this->engine->handle(AccountLocked::draft($source, $uid, $linkId, $link['sent_to_hint'], $link['detection_id'], $change, $ended, $lastAdmin));
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection locked the account {uid} but could not record it', ['uid' => $uid, 'exception' => $e]);
		}
		return $lastAdmin ? self::SESSIONS_ENDED : self::LOCKED;
	}

	/**
	 * Enable an account that was locked with a lock link, and start the
	 * "Secure my account" checklist for its owner.
	 *
	 * @return self::REENABLED|self::NOT_LOCKED|self::NO_ACCOUNT|self::NOT_A_LOCK
	 */
	public function reenable(Detection $detection, string $actor): string {
		if ($detection->getCheckId() !== AccountLocked::ID) {
			return self::NOT_A_LOCK;
		}
		$user = $detection->getUid() === null ? null : $this->userManager->get($detection->getUid());
		if ($user === null) {
			return self::NO_ACCOUNT;
		}
		if ($user->isEnabled()) {
			return self::NOT_LOCKED;
		}
		$user->setEnabled(true);
		$this->passwords->require($user->getUID(), $detection->getId(), AccountLocked::ID);
		$this->guide->start($user->getUID(), SecureAccountGuide::REASON_REENABLED, $detection->getId(), $detection->getCreatedAt());
		$this->audit->log('account %s enabled again by %s after it was locked with the lock link (detection %s)', ['uid' => $user->getUID(), 'actor' => $actor, 'detection' => $detection->getId()]);
		return self::REENABLED;
	}
}
