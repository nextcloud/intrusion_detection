<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\AccountTakeover;

/**
 * Why an account takeover detection fired, as stored in its facts.
 */
enum AccountTakeoverRule: string {
	/** Changes in the session of a risky login */
	case RiskyLogin = 'risky_login';
	/** Changes from all sessions */
	case AnySession = 'any_session';
}
