<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Definition;

use OCP\IL10N;

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

	/**
	 * The group heading on the admin page.
	 */
	public function label(IL10N $l): string {
		return match ($this) {
			self::LoginAttacks => $l->t('Login attacks'),
			self::Traps => $l->t('Traps'),
			self::SharesAndReset => $l->t('Shares and password reset'),
			self::DevicesAndSessions => $l->t('Devices and sessions'),
			self::InsideTheAccount => $l->t('Inside the account'),
			self::Administration => $l->t('Administration'),
			self::AddressesAndRequests => $l->t('Addresses and requests'),
			self::Internal => $l->t('Raised by Nextcloud itself'),
		};
	}
}
