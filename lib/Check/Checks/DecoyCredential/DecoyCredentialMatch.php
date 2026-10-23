<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\DecoyCredential;

/**
 * What of a decoy was used, as stored in the facts of its detection.
 */
enum DecoyCredentialMatch: string {
	/** Its secret */
	case Secret = 'secret';
	/** Only its login name */
	case LoginName = 'login_name';
}
