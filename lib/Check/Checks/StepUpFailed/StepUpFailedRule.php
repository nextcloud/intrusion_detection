<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\StepUpFailed;

/**
 * How a login that needed extra confirmation failed, as stored in its facts.
 */
enum StepUpFailedRule: string {
	/** Too many wrong codes */
	case Attempts = 'attempts';
	/** Not confirmed in time */
	case Timeout = 'timeout';
	/** The session of an unconfirmed login came back without its confirmation state */
	case Resumed = 'resumed';
	/** An administrator rejected the login */
	case Rejected = 'rejected';
}
