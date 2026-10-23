<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Notification\AdminNotices;
use OCP\IUser;
use OCP\IUserManager;

/**
 * Requires a new password at the next login (concept section 11.7).
 *
 * The next browser login goes to the password page first; logins with the
 * password from apps and scripts are refused until then, while app
 * passwords keep working. Choosing a new password anywhere lifts it.
 *
 * Accounts whose password Nextcloud cannot change (LDAP, SAML and other
 * external directories) are never sent to the password page: the
 * administrators are asked to reset the password in that directory instead.
 */
class PasswordChangeService {
	public const STATE_REQUIRED = 'required';
	public const STATE_EXTERNAL = 'external';
	public const STATE_NO_USER = 'no_user';
	/** Counter key for notices that are not about a detection */
	public const NOTICE_CHECK = 'force_password_change';

	public function __construct(
		private readonly PasswordChangeFlag $flag,
		private readonly IUserManager $userManager,
		private readonly AdminNotices $adminNotices,
		private readonly AuditLogger $audit,
	) {
	}

	/**
	 * @return self::STATE_* what happened
	 */
	public function require(string $uid, ?string $detectionId = null, string $checkId = self::NOTICE_CHECK): string {
		$user = $this->userManager->get($uid);
		if ($user === null) {
			return self::STATE_NO_USER;
		}
		if (!$user->canChangePassword()) {
			$this->external($user, $detectionId, $checkId);
			return self::STATE_EXTERNAL;
		}
		$this->flag->set($uid);
		$this->audit->log('new password required for %s (detection %s)', ['uid' => $uid, 'detection' => $detectionId]);
		return self::STATE_REQUIRED;
	}

	public function isRequired(string $uid): bool {
		return $this->flag->isRequired($uid);
	}

	public function requiredSince(string $uid): ?int {
		return $this->flag->requiredSince($uid);
	}

	/**
	 * @return bool whether a new password was required
	 */
	public function clear(string $uid, string $actor): bool {
		$cleared = $this->flag->clear($uid);
		if ($cleared) {
			$this->audit->log('new password no longer required for %s (%s)', ['uid' => $uid, 'actor' => $actor]);
		}
		return $cleared;
	}

	/**
	 * The account's password is managed elsewhere: ask the administrators to
	 * reset it there, and do not keep a requirement the user cannot meet.
	 */
	public function external(IUser $user, ?string $detectionId = null, string $checkId = self::NOTICE_CHECK): void {
		$this->adminNotices->externalPassword($user->getUID(), $detectionId, $checkId);
		$this->clear($user->getUID(), 'password managed outside Nextcloud');
		$this->audit->log('password of %s must be reset in its external directory (detection %s)', ['uid' => $user->getUID(), 'detection' => $detectionId]);
	}
}
