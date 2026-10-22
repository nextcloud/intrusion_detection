<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\InjectionProbe;

/**
 * Brings a value into the one form the signatures are written for, so that
 * encoding tricks do not hide a payload:
 *
 * - URL-decoded up to twice (double encoding is a common evasion), stopping
 *   as soon as decoding changes nothing
 * - null bytes removed
 * - lower-cased (ASCII only, so invalid UTF-8 is harmless)
 * - SQL comments replaced by a space; the content of MySQL's executable
 *   comments (`/*!50000 union*\/`) is kept, because MySQL runs it
 * - whitespace, including `+`, tab and newline, collapsed to one space
 */
class Normalizer {
	public const MAX_DECODE_ROUNDS = 2;

	public function normalize(string $value): string {
		$value = self::urlDecode($value);
		$value = strtolower(str_replace("\0", '', $value));
		if (str_contains($value, '/*')) {
			$value = preg_replace('~/\*(?!!)[^*]{0,64}\*/~', ' ', $value) ?? $value;
			$value = preg_replace('~/\*!\d{0,6}|\*/~', ' ', $value) ?? $value;
		}
		return trim(preg_replace('~[\s+]+~', ' ', $value) ?? $value);
	}

	/**
	 * URL-decode up to MAX_DECODE_ROUNDS times. A `+` is left alone: the
	 * whitespace rule turns it into a space anyway.
	 */
	public static function urlDecode(string $value): string {
		for ($round = 0; $round < self::MAX_DECODE_ROUNDS && str_contains($value, '%'); $round++) {
			$decoded = rawurldecode($value);
			if ($decoded === $value) {
				break;
			}
			$value = $decoded;
		}
		return $value;
	}

}
