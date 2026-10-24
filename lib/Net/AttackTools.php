<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Net;

/**
 * Recognises the user agents of attack tools and scripting libraries on
 * failed password logins (concept section 10.18), from a built-in list.
 */
class AttackTools {
	/** Only the start of a user agent is looked at */
	private const MAX_USER_AGENT = 512;

	/**
	 * The built-in tools, matched as words at the start of the user agent or
	 * after a separator, case-insensitively. Bounded, no nested quantifiers.
	 */
	public const BUILTIN = '~(?:^|[\s(;/,])(hydra|medusa|ncrack|nikto|sqlmap|zgrab|masscan|nmap|python-requests|go-http-client|curl|wget|libwww-perl|java/)~i';

	/**
	 * The tool a user agent names, or null.
	 */
	public function match(?string $userAgent): ?string {
		if ($userAgent === null || $userAgent === '') {
			return null;
		}
		$userAgent = substr($userAgent, 0, self::MAX_USER_AGENT);
		if (preg_match(self::BUILTIN, $userAgent, $m) === 1) {
			return rtrim(strtolower($m[1]), '/');
		}
		return null;
	}
}
