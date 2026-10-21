<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Sensitive;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Lockdown\LockdownEffect;
use OCA\IntrusionDetection\Lockdown\LockdownState;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IGroupManager;

/**
 * Whether a session is risky, so that sensitive actions need a fresh
 * confirmation (concept section 11.13), and when it last confirmed one.
 *
 * A session is risky when
 * - lockdown mode is on, with that effect (every session);
 * - its login was allowed without a confirmation (`confirmed_by` none);
 * - a detection applied `confirm_sensitive` to it, in this request
 *   (kept in the session) or in another one ({@see RiskySessions});
 * - it is an administrator's, `sensitive_admins_always` is on, and its last
 *   strong confirmation (a second factor, an email code, an administrator's
 *   approval, or a confirmed sensitive action) is older than
 *   `sensitive_admin_max_age`.
 *
 * A confirmation counts for `sensitive_confirm_ttl`. Everything here is
 * kept in the PHP session; it is only asked on sensitive routes.
 */
class SensitiveSession {
	public const REASON_LOCKDOWN = 'lockdown';
	public const REASON_UNCONFIRMED_LOGIN = 'unconfirmed_login';
	public const REASON_DETECTION = 'detection';
	public const REASON_ADMIN = 'admin';

	/** The confirmations of a login that prove who holds the account */
	public const STRONG_METHODS = [IConfirmationMethod::SECOND_FACTOR, IConfirmationMethod::EMAIL_CODE, IConfirmationMethod::ADMIN_APPROVAL];

	public function __construct(
		private readonly Settings $settings,
		private readonly LockdownState $lockdown,
		private readonly RiskySessions $marks,
		private readonly IGroupManager $groupManager,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * Why the session is risky, or null when it is not. The cheap reasons
	 * are asked first; the database only when other requests marked
	 * sessions risky recently.
	 *
	 * @return ?self::REASON_*
	 */
	public function riskReason(SessionState $state, string $uid): ?string {
		if ($this->lockdown->applies(LockdownEffect::Sensitive)) {
			return self::REASON_LOCKDOWN;
		}
		$confirmation = $state->get(SessionState::CONFIRMATION);
		if ($confirmation !== null && ($confirmation['uid'] ?? null) === $uid && ($confirmation['by'] ?? null) === StepUpService::CONFIRMED_BY_NONE) {
			return self::REASON_UNCONFIRMED_LOGIN;
		}
		$risky = $state->get(SessionState::RISKY);
		if ($risky !== null && ($risky['uid'] ?? null) === $uid) {
			return self::REASON_DETECTION;
		}
		if ($this->marks->isMarked($uid)) {
			return self::REASON_DETECTION;
		}
		if ($this->settings->getBool(GlobalSettings::SENSITIVE_ADMINS_ALWAYS)
			&& $this->groupManager->isAdmin($uid)
			&& $this->timeFactory->getTime() - $this->lastStrong($state, $uid) > $this->settings->getInt(GlobalSettings::SENSITIVE_ADMIN_MAX_AGE)) {
			return self::REASON_ADMIN;
		}
		return null;
	}

	/**
	 * Whether the session confirmed a sensitive action within `sensitive_confirm_ttl`.
	 */
	public function isConfirmed(SessionState $state, string $uid): bool {
		$sensitive = $this->sensitive($state, $uid);
		$at = $sensitive['confirmedAt'] ?? null;
		return is_int($at) && $this->timeFactory->getTime() - $at < $this->settings->getInt(GlobalSettings::SENSITIVE_CONFIRM_TTL);
	}

	/**
	 * When the session's holder last proved who they are, or 0 for never.
	 */
	public function lastStrong(SessionState $state, string $uid): int {
		$last = 0;
		$confirmation = $state->get(SessionState::CONFIRMATION);
		if ($confirmation !== null && ($confirmation['uid'] ?? null) === $uid
			&& in_array($confirmation['by'] ?? null, self::STRONG_METHODS, true) && is_int($confirmation['at'] ?? null)) {
			$last = (int)$confirmation['at'];
		}
		$sensitive = $this->sensitive($state, $uid);
		foreach (['strongAt', 'confirmedAt'] as $key) {
			$at = $sensitive[$key] ?? null;
			if (is_int($at)) {
				$last = max($last, $at);
			}
		}
		return $last;
	}

	/**
	 * A sensitive action was confirmed with this method.
	 */
	public function confirmed(SessionState $state, string $uid, string $method): void {
		$now = $this->timeFactory->getTime();
		$state->set(SessionState::SENSITIVE, ['uid' => $uid, 'confirmedAt' => $now, 'strongAt' => $now, 'by' => $method]);
	}

	/**
	 * The session's holder solved their second factor: a strong
	 * confirmation, but not of a sensitive action.
	 */
	public function strongConfirmation(SessionState $state, string $uid): void {
		$sensitive = $this->sensitive($state, $uid) ?? ['uid' => $uid];
		$sensitive['strongAt'] = $this->timeFactory->getTime();
		$state->set(SessionState::SENSITIVE, $sensitive);
	}

	/**
	 * A detection in this request made the session risky.
	 */
	public function markRisky(SessionState $state, string $uid, string $checkId, ?int $detectionId): bool {
		return $state->set(SessionState::RISKY, ['uid' => $uid, 'check' => $checkId, 'detection' => $detectionId, 'at' => $this->timeFactory->getTime()]);
	}

	/**
	 * @return ?array<string, mixed>
	 */
	private function sensitive(SessionState $state, string $uid): ?array {
		$sensitive = $state->get(SessionState::SENSITIVE);
		return $sensitive !== null && ($sensitive['uid'] ?? null) === $uid ? $sensitive : null;
	}
}
