<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Risk;

use OCA\IntrusionDetection\Check\Payload\CustomSignatures;

/**
 * Recognises the user agents of attack tools and scripting libraries on
 * failed password logins (concept section 10.18): a built-in list, plus
 * regular expressions the administrator adds.
 *
 * Custom patterns are validated like custom payload signatures: they must
 * compile, may not match an empty user agent, and must stay fast on long
 * adversarial input. They run with a low backtracking limit; a failure
 * counts as no match.
 */
class AttackTools {
	public const MAX_PATTERNS = 20;
	public const MAX_PATTERN_LENGTH = 200;
	/** Longest tool name kept, so it fits the flag's reason column */
	public const MAX_NAME_LENGTH = 32;
	/** Only the start of a user agent is looked at */
	private const MAX_USER_AGENT = 512;

	/**
	 * The built-in tools, matched as words at the start of the user agent or
	 * after a separator, case-insensitively. Bounded, no nested quantifiers.
	 */
	public const BUILTIN = '~(?:^|[\s(;/,])(hydra|medusa|ncrack|nikto|sqlmap|zgrab|masscan|nmap|python-requests|go-http-client|curl|wget|libwww-perl|java/)~i';

	private const DELIMITER = "\x01";

	/**
	 * The tool a user agent names, or null.
	 *
	 * @param list<string> $customPatterns
	 */
	public function match(?string $userAgent, array $customPatterns = []): ?string {
		if ($userAgent === null || $userAgent === '') {
			return null;
		}
		$userAgent = substr($userAgent, 0, self::MAX_USER_AGENT);
		if (preg_match(self::BUILTIN, $userAgent, $m) === 1) {
			return rtrim(strtolower($m[1]), '/');
		}
		foreach ($customPatterns as $pattern) {
			if (self::problem($pattern, false) !== null) {
				continue;
			}
			$match = null;
			if (CustomSignatures::run(self::compile($pattern), $userAgent, $match) === 1) {
				/** @var array<int, array{0: string, 1: int}> $match */
				return self::name($match[0][0] ?? '');
			}
		}
		return null;
	}

	/**
	 * Why a custom pattern cannot be used, or null when it can.
	 *
	 * @param bool $thorough also run the timing test (when saving)
	 */
	public static function problem(string $pattern, bool $thorough = true): ?string {
		if (strlen($pattern) > self::MAX_PATTERN_LENGTH) {
			return CustomSignatures::PROBLEM_TOO_LONG;
		}
		if (trim($pattern) === '') {
			return CustomSignatures::PROBLEM_INVALID;
		}
		// A weight prefix makes the whole entry the pattern body, so exactly this pattern is checked.
		return (new CustomSignatures())->problem(CustomSignatures::DEFAULT_WEIGHT . ':' . $pattern, $thorough);
	}

	private static function compile(string $pattern): string {
		return self::DELIMITER . $pattern . self::DELIMITER . 'i';
	}

	/**
	 * A matched text as a short, printable name.
	 */
	private static function name(string $matched): string {
		$name = trim(preg_replace('/[^\x20-\x7e]+/', '', $matched) ?? '');
		return $name === '' ? 'custom' : substr(strtolower($name), 0, self::MAX_NAME_LENGTH);
	}
}
