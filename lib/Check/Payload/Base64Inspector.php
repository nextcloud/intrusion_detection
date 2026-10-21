<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Payload;

/**
 * Finds text hidden in base64.
 *
 * A candidate is 16 to 8 192 characters of standard base64 with correct
 * padding, or of URL-safe base64 with correct padding or none. It is decoded
 * strictly and must be canonical (re-encoding gives the same characters).
 * Decoded data that is less than 90 % printable ASCII is binary (encrypted
 * state, ids, images) and not an attack payload. Text that is itself base64
 * is decoded once more, at most two levels in all.
 */
class Base64Inspector {
	public const MIN_LENGTH = 16;
	public const MAX_LENGTH = 8192;
	public const MAX_LEVELS = 2;
	public const MIN_PRINTABLE_RATIO = 0.9;

	/**
	 * @return list<string> the decoded text of each level, outermost first; empty when the value is no base64 text
	 */
	public function decode(string $value): array {
		$levels = [];
		$candidate = trim($value);
		for ($level = 0; $level < self::MAX_LEVELS; $level++) {
			$decoded = $this->decodeOnce($candidate);
			if ($decoded === null) {
				break;
			}
			$levels[] = $decoded;
			$candidate = trim($decoded);
		}
		return $levels;
	}

	/**
	 * A form field as base64 candidate: URL-decoded, and with spaces turned
	 * back into `+`, which PHP turns into spaces when it parses a form.
	 */
	public static function formCandidate(string $value): string {
		$value = Normalizer::urlDecode($value);
		if (str_contains($value, ' ') && preg_match('~^[A-Za-z0-9+/ ]+={0,2}$~D', $value) === 1) {
			$value = str_replace(' ', '+', $value);
		}
		return $value;
	}

	public function decodeOnce(string $value): ?string {
		$length = strlen($value);
		if ($length < self::MIN_LENGTH || $length > self::MAX_LENGTH) {
			return null;
		}
		$standard = $length % 4 === 0 && preg_match('~^[A-Za-z0-9+/]+={0,2}$~D', $value) === 1;
		if (!$standard) {
			if (preg_match('~^[A-Za-z0-9_-]+(={0,2})$~D', $value, $m) !== 1) {
				return null;
			}
			// Padded URL-safe base64 must be padded correctly; unpadded may not leave a single character.
			if ($m[1] !== '' ? $length % 4 !== 0 : $length % 4 === 1) {
				return null;
			}
			$value = strtr(rtrim($value, '='), '-_', '+/');
			$value .= str_repeat('=', (4 - strlen($value) % 4) % 4);
		}
		$decoded = base64_decode($value, true);
		if ($decoded === false || $decoded === '' || base64_encode($decoded) !== $value) {
			return null;
		}
		return $this->isText($decoded) ? $decoded : null;
	}

	private function isText(string $data): bool {
		$printable = strlen(preg_replace('~[^\x20-\x7e\t\r\n]+~', '', $data) ?? '');
		return $printable >= self::MIN_PRINTABLE_RATIO * strlen($data);
	}
}
