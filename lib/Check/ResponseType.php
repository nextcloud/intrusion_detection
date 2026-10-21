<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

use OCP\IL10N;

/**
 * What Nextcloud can do about a detection.
 *
 * The response engine runs them in the order of {@see self::order()}: blocks
 * first, notifications last, so that a notification can say what was done.
 */
enum ResponseType: string {
	case Ban = 'ban';
	case RevokeToken = 'revoke_token';
	case KillSession = 'kill_session';
	case ForcePasswordChange = 'force_password_change';
	case ProtectAccount = 'protect_account';
	case FlagSource = 'flag_source';
	case FlagPassword = 'flag_password';
	case SuppressResetMail = 'suppress_reset_mail';
	case RateLimit = 'rate_limit';
	case StepUp = 'step_up';
	case ConfirmSensitive = 'confirm_sensitive';
	case LockLink = 'lock_link';
	case NotifyAdmin = 'notify_admin';
	case NotifyUser = 'notify_user';
	case NotifyShareOwner = 'notify_share_owner';

	public function order(): int {
		return match ($this) {
			self::Ban => 10,
			self::RevokeToken => 20,
			self::KillSession => 21,
			self::ForcePasswordChange => 30,
			self::ProtectAccount => 40,
			self::FlagSource => 41,
			self::FlagPassword => 42,
			self::SuppressResetMail => 43,
			self::RateLimit => 44,
			self::StepUp => 50,
			self::ConfirmSensitive => 51,
			self::LockLink => 60,
			self::NotifyAdmin => 90,
			self::NotifyUser => 91,
			self::NotifyShareOwner => 92,
		};
	}

	public function isNotification(): bool {
		return $this->order() >= 90;
	}

	/**
	 * One line shown next to the response's checkbox on the admin page.
	 */
	public function describe(IL10N $l): string {
		return match ($this) {
			self::Ban => $l->t('Block the address for hours, longer if it comes back.'),
			self::RevokeToken => $l->t('Revoke the app password or token that was used.'),
			self::KillSession => $l->t('End the suspicious session and the app passwords created from it.'),
			self::ForcePasswordChange => $l->t('Require a new password at the next login.'),
			self::ProtectAccount => $l->t('Ask for extra confirmation at every password login to this account for a while.'),
			self::FlagSource => $l->t('Mark the address, so that successful logins from it need extra confirmation.'),
			self::FlagPassword => $l->t('Remember the guessed password for a day, so that logins with it need extra confirmation.'),
			self::SuppressResetMail => $l->t('Stop sending password reset emails to the flooded account for a while. Whoever asks gets the usual answer.'),
			self::RateLimit => $l->t('Refuse further requests of this kind for a few minutes.'),
			self::StepUp => $l->t('Ask the user to confirm the login with their second factor or an email code.'),
			self::ConfirmSensitive => $l->t('Ask for confirmation before sensitive actions for the rest of the session.'),
			self::LockLink => $l->t('Email the previous address a link to lock the account.'),
			self::NotifyAdmin => $l->t('Notify the administrators.'),
			self::NotifyUser => $l->t('Tell the affected user, with "Was this you?" where it applies.'),
			self::NotifyShareOwner => $l->t('Tell the owner of the share.'),
		};
	}

	/**
	 * The response in the "What happens" text of the admin page: like
	 * {@see self::describe()}, but with the settings it depends on as `{name}`
	 * placeholders, which the page fills in while the admin types.
	 */
	public function happens(IL10N $l): string {
		return match ($this) {
			self::Ban => $l->t('The address is blocked for {ban_duration_1} ({ban_duration_2} if it is blocked again within {ban_history_days} days, then {ban_duration_3}).'),
			self::FlagSource => $l->t('Successful logins from the address need extra confirmation for {flag_duration}.'),
			self::FlagPassword => $l->t('Logins with the guessed password need extra confirmation for {flag_duration}.'),
			default => $this->describe($l),
		};
	}
}
