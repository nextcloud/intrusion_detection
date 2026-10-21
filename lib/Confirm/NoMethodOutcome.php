<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCP\IL10N;

/**
 * What happens to a login that needs extra confirmation when the account
 * has no way to confirm it: no second factor, no email address (and none of
 * the further methods).
 */
enum NoMethodOutcome: string {
	/** The login is refused; the administrators are told */
	case Refuse = 'refuse';
	/** The login is allowed; the user and the administrators are told */
	case AllowNotify = 'allow_notify';
	/** The login is allowed, and a new password is required */
	case AllowForceChange = 'allow_force_change';

	public function label(IL10N $l): string {
		return match ($this) {
			self::Refuse => $l->t('Refuse the login'),
			self::AllowNotify => $l->t('Allow it and tell the user and you'),
			self::AllowForceChange => $l->t('Allow it and require a new password'),
		};
	}

	public function description(IL10N $l): string {
		return match ($this) {
			self::Refuse => $l->t('The person sees a reference to give you, and you are told. Safest, but it can lock out someone who only lacks an email address.'),
			self::AllowNotify => $l->t('The login goes ahead without a confirmation. The user and you are told, and the session counts as risky.'),
			self::AllowForceChange => $l->t('The login goes ahead, but the user must choose a new password first.'),
		};
	}

	/**
	 * @return list<string>
	 */
	public static function values(): array {
		return array_map(static fn (self $o): string => $o->value, self::cases());
	}
}
