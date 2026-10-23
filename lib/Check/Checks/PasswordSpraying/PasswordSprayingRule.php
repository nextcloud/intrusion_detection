<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\PasswordSpraying;

/**
 * Why a password spraying detection fired, as stored in its facts.
 */
enum PasswordSprayingRule: string {
	/** One password failed for many accounts */
	case Spray = 'spray';
	/** An address tried a password that is flagged already */
	case Flagged = 'flagged_password';
	/** A successful login with a flagged password */
	case Login = 'login_success';
}
