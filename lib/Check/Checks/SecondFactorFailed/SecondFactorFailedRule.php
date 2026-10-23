<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\SecondFactorFailed;

/**
 * Why a second factor failure detection fired, as stored in its facts.
 */
enum SecondFactorFailedRule: string {
	/** Too many failures in one login */
	case Login = 'login';
	/** Too many failures for the account within an hour */
	case Hour = 'hour';
	/** The address was flagged after an earlier attack */
	case Flagged = 'flagged';
}
