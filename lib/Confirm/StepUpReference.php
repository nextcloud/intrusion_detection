<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Response\BanService;

/**
 * The reference a refused login shows ("Reference: SAAA-AAAA-AAAA-AB3"),
 * so that an administrator can look the refusal up. It encodes the id of
 * the refusal's detection in the alphabet of block references, after the
 * letter S, in groups of four.
 */
final class StepUpReference {
	public const PREFIX = 'S';
	/** Enough base-32 digits for any 63-bit snowflake id */
	private const DIGITS = 13;

	public static function of(string $detectionId): string {
		$alphabet = BanService::REFERENCE_CHARS;
		$base = strlen($alphabet);
		$digits = '';
		$value = max(0, (int)$detectionId);
		for ($i = 0; $i < self::DIGITS; $i++) {
			$digits = $alphabet[$value % $base] . $digits;
			$value = intdiv($value, $base);
		}
		return implode('-', str_split(self::PREFIX . $digits, 4));
	}

	/**
	 * The detection id in a reference as typed by a person (any case, with or
	 * without the dashes), or null when it is not one.
	 */
	public static function detectionId(string $input): ?string {
		$reference = Ban::normaliseReference($input);
		if (strlen($reference) !== 1 + self::DIGITS || $reference[0] !== self::PREFIX) {
			return null;
		}
		$alphabet = BanService::REFERENCE_CHARS;
		$value = 0;
		for ($i = 1; $i <= self::DIGITS; $i++) {
			$digit = strpos($alphabet, $reference[$i]);
			if ($digit === false || $value > intdiv(PHP_INT_MAX - $digit, strlen($alphabet))) {
				return null;
			}
			$value = $value * strlen($alphabet) + $digit;
		}
		return $value > 0 ? (string)$value : null;
	}
}
