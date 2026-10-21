<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Takeover;

use OCP\IL10N;

/**
 * The kinds of security changes the log records (concept sections 7 and
 * 10.14). Every kind except a revoked app password counts towards the
 * account takeover check with the points of its parameter.
 */
enum SecurityChangeType: string {
	case EmailChanged = 'email_changed';
	case PasswordChanged = 'password_changed';
	case SecondFactorAdded = 'second_factor_added';
	/** One second factor removed while others remain */
	case SecondFactorRemoved = 'second_factor_removed';
	/** The last second factor removed: the account has none any more */
	case SecondFactorDisabled = 'second_factor_disabled';
	case AppPasswordCreated = 'app_password_created';
	case DeviceConnected = 'device_connected';
	case AppPasswordRevoked = 'app_password_revoked';

	/**
	 * The parameter of the takeover check that holds this kind's points, or
	 * null for kinds that never count.
	 */
	public function pointsParam(): ?string {
		return $this === self::AppPasswordRevoked ? null : 'points_' . $this->value;
	}

	public function label(IL10N $l): string {
		return match ($this) {
			self::EmailChanged => $l->t('Email address changed'),
			self::PasswordChanged => $l->t('Password changed'),
			self::SecondFactorAdded => $l->t('Second factor added'),
			self::SecondFactorRemoved => $l->t('Second factor removed'),
			self::SecondFactorDisabled => $l->t('Two-factor authentication turned off'),
			self::AppPasswordCreated => $l->t('App password created'),
			self::DeviceConnected => $l->t('Device connected'),
			self::AppPasswordRevoked => $l->t('App password revoked'),
		};
	}
}
