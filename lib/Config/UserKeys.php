<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

/**
 * The app's per-user config keys, declared in {@see Lexicon::getUserConfigs()}.
 */
final class UserKeys {
	/** When the password was last checked against the breach list */
	public const BREACH_CHECKED_AT = 'breach_checked_at';
	/** The current password was found on the breach list */
	public const BREACHED = 'breached';
	/** When a new password was required at the next login */
	public const FORCE_PASSWORD_CHANGE = 'force_password_change';
	/** When the oldest security event happened that the user has not seen at a login yet */
	public const LOGIN_NOTICE_SINCE = 'login_notice_since';
	/** Second factors set up from a session whose login proved only the password */
	public const UNTRUSTED_SECOND_FACTORS = 'untrusted_second_factors';
	/** When the account's recent confirmation codes were sent */
	public const CODE_MAILS = 'code_mails';
	/** When wrong confirmation codes were entered for the account, across its logins */
	public const CODE_WRONG = 'code_wrong';
	/** Progress through the "Secure my account" checklist */
	public const SECURE_GUIDE = 'secure_guide';
	/** When the user was last reminded of app passwords and devices they have not used for 90 days */
	public const STALE_CREDENTIALS_NOTIFIED_AT = 'stale_credentials_notified_at';
}
