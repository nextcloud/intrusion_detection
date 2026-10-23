<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\ShareBruteforce;

/**
 * Why a share link attack detection fired, as stored in its facts.
 */
enum ShareBruteforceRule: string {
	/** One address tried many unknown links */
	case Tokens = 'tokens';
	/** The addresses of one IPv4 /24 together */
	case TokensNetwork = 'tokens_network';
	/** One address entered many wrong passwords for a share */
	case PasswordSource = 'password_source';
	/** A share got many wrong passwords from any number of addresses */
	case PasswordShare = 'password_share';
}
