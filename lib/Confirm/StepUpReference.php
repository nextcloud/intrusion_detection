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
 * The reference a refused login shows ("Reference: SAAA-AAB3"), so that an
 * administrator can look the refusal up. It encodes the id of the refusal's
 * detection in the alphabet and shape of block references, with the
 * leading letter S; the lookup tries blocks first.
 */
final class StepUpReference {
	public const PREFIX = 'S';
	private const DIGITS = 7;

	public static function of(int $detectionId): string {
		$alphabet = BanService::REFERENCE_CHARS;
		$base = strlen($alphabet);
		$digits = '';
		$value = max(0, $detectionId);
		for ($i = 0; $i < self::DIGITS; $i++) {
			$digits = $alphabet[$value % $base] . $digits;
			$value = intdiv($value, $base);
		}
		return Ban::formatReference(self::PREFIX . $digits);
	}

	/**
	 * The detection id in a reference as typed by a person (any case, with or
	 * without the dash), or null when it is not one.
	 */
	public static function detectionId(string $input): ?int {
		$reference = Ban::normaliseReference($input);
		if (strlen($reference) !== 1 + self::DIGITS || $reference[0] !== self::PREFIX) {
			return null;
		}
		$alphabet = BanService::REFERENCE_CHARS;
		$value = 0;
		for ($i = 1; $i <= self::DIGITS; $i++) {
			$digit = strpos($alphabet, $reference[$i]);
			if ($digit === false) {
				return null;
			}
			$value = $value * strlen($alphabet) + $digit;
		}
		return $value > 0 ? $value : null;
	}
}
