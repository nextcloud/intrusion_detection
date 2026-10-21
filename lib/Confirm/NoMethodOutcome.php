<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

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

	/**
	 * @return list<string>
	 */
	public static function values(): array {
		return array_map(static fn (self $o): string => $o->value, self::cases());
	}
}
