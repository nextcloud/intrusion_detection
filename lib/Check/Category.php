<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

/**
 * Groups of checks, in the order the admin page shows them.
 */
enum Category: string {
	case LoginAttacks = 'login_attacks';
	case Traps = 'traps';
	case SharesAndReset = 'shares_reset';
	case DevicesAndSessions = 'devices_sessions';
	case InsideTheAccount = 'inside_account';
	case Administration = 'administration';
	case AddressesAndRequests = 'addresses_requests';
	/** Checks the system raises itself, shown in the overview but not as cards */
	case Internal = 'internal';
}
