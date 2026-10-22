<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Takeover;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\AccountLocked\AccountLocked;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Guide\SecureAccountGuide;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Notification\AdminAlerts;
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
 * administrators. It never unlocks or changes anything else. Only an
 * administrator enables the account again, which starts the "Secure my
 * account" checklist for its owner.
 */
class AccountLock {
	public const LOCKED = 'locked';

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
	 * @return LockLinks::VALID|LockLinks::USED|LockLinks::EXPIRED|LockLinks::INVALID|self::LOCKED what happened: LOCKED, or why not
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

		$ended = $this->tokens->invalidateAll($uid);
		if ($this->userSession->getUser()?->getUID() === $uid) {
			$this->userSession->logout();
		}
		$user->setEnabled(false);
		$this->audit->log('account %s locked with the lock link sent to %s', ['uid' => $uid, 'sentTo' => $link['sent_to_hint']]);

		$change = $link['change_id'] === null ? null : $this->changes->find($link['change_id']);
		try {
			$this->engine->handle(new DetectionDraft(
				checkId: AccountLocked::ID,
				source: $source,
				uid: $uid,
				facts: [
					'link' => $linkId,
					'sentTo' => $link['sent_to_hint'],
					'newAddress' => $change['new_value_hint'] ?? null,
					'changedAt' => $change['created_at'] ?? null,
					'changedFrom' => $change['ip'] ?? null,
					'takeoverDetection' => $link['detection_id'],
					'tokensEnded' => count($ended),
					'ended' => array_slice($ended, 0, 50),
					AdminAlerts::FACT_ALL_ADMINS => true,
				],
			), null, new ModeState(Mode::Protect, Mode::Protect));
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection locked the account {uid} but could not record it', ['uid' => $uid, 'exception' => $e]);
		}
		return self::LOCKED;
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
		$this->guide->start($user->getUID(), SecureAccountGuide::REASON_REENABLED, $detection->getId(), $detection->getCreatedAt());
		$this->audit->log('account %s enabled again by %s after it was locked with the lock link (detection %s)', ['uid' => $user->getUID(), 'actor' => $actor, 'detection' => $detection->getId()]);
		return self::REENABLED;
	}
}
