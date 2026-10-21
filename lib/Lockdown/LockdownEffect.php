<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Lockdown;

use OCP\IL10N;

/**
 * What lockdown mode does while it lasts (concept section 11.14). Each
 * effect can be switched off in `lockdown_effects`; all are on by default.
 */
enum LockdownEffect: string {
	/** Every password login needs extra confirmation (step-up policy "lockdown") */
	case Login = 'login';
	/** Every session counts as risky, so sensitive actions need confirmation */
	case Sensitive = 'sensitive';
	/** No new app passwords or device connections */
	case Devices = 'devices';
	/** No password reset emails */
	case Reset = 'reset';
	/** The count limits of the login, share and reset checks are multiplied by `lockdown_factor` */
	case Limits = 'limits';
	/** Share password guessing: at most SHARE_PASSWORD_LIMIT wrong passwords per address */
	case SharePassword = 'share_password';

	public const PATTERN = '/^(login|sensitive|devices|reset|limits|share_password)$/';
	/** Wrong share passwords from one address that make a detection during lockdown */
	public const SHARE_PASSWORD_LIMIT = 3;
	public const MIN_DURATION = 3600;
	public const MAX_DURATION = 86400;
	/** The longest reason an administrator can give, in bytes */
	public const MAX_REASON = 200;
	/** The longest login page notice, in bytes */
	public const MAX_NOTICE = 500;

	/**
	 * @return list<string>
	 */
	public static function values(): array {
		return array_map(static fn (self $e): string => $e->value, self::cases());
	}

	public function label(IL10N $l): string {
		return match ($this) {
			self::Login => $l->t('Confirm every password login'),
			self::Sensitive => $l->t('Confirm sensitive actions in every session'),
			self::Devices => $l->t('No new app passwords or device connections'),
			self::Reset => $l->t('Pause password reset'),
			self::Limits => $l->t('Lower the limits of the checks'),
			self::SharePassword => $l->t('Stricter share password limit'),
		};
	}

	/**
	 * What the effect does, with the settings it depends on as `{name}` placeholders.
	 */
	public function description(IL10N $l): string {
		return match ($this) {
			self::Login => $l->t('Every login with a password needs a second factor, an email code or an administrator\'s approval. Remembered devices do not count unless you allow them. Logins that nothing can confirm are refused. App passwords keep working.'),
			self::Sensitive => $l->t('Changing an email address or password, removing a second factor, creating app passwords, sharing large folders publicly and administration need a fresh confirmation, in every session.'),
			self::Devices => $l->t('Creating app passwords and connecting new devices and desktop or mobile clients is refused. Devices that are already connected keep working.'),
			self::Reset => $l->t('No password reset emails are sent. The reset page still shows its usual answer, so nobody learns anything from it.'),
			self::Limits => $l->t('The count limits of the login, share and password reset checks are multiplied by {lockdown_factor}, but never go below 2.'),
			self::SharePassword => $l->t('Wrong passwords for a share link: the check for share link attacks acts after %s from one address instead of its usual limit.', [(string)self::SHARE_PASSWORD_LIMIT]),
		};
	}
}
