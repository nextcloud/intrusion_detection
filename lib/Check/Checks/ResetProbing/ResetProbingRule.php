<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\ResetProbing;

/**
 * Why a reset probing detection fired, as stored in its facts.
 */
enum ResetProbingRule: string {
	/** One address asked for many names or email addresses */
	case Enumeration = 'enumeration';
	/** Many requests for one account */
	case Flood = 'flood';
}
