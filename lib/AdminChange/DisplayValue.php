<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AdminChange;

/**
 * Shortened, printable copies of setting values for detections and the
 * snapshot: strings of at most 200 characters without control characters,
 * lists of at most 20 entries, nested values as short text.
 *
 * Only ever used for values that are not secret.
 */
final class DisplayValue {
	public const MAX_TEXT = 200;
	public const MAX_ITEMS = 20;

	public static function shorten(mixed $value): mixed {
		if ($value === null || is_bool($value) || is_int($value) || is_float($value)) {
			return $value;
		}
		if (is_string($value)) {
			return self::text($value);
		}
		if (is_array($value)) {
			$items = [];
			foreach ($value as $key => $item) {
				if (count($items) >= self::MAX_ITEMS) {
					$items[] = '…';
					break;
				}
				$text = is_array($item) ? self::text(json_encode($item, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR) ?: '') : self::shorten($item);
				$items[] = is_string($key) ? self::text($key . ': ' . self::asText($text)) : $text;
			}
			return $items;
		}
		return gettype($value);
	}

	public static function encode(mixed $value): string {
		return json_encode(self::shorten($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR) ?: 'null';
	}

	/**
	 * @return mixed the shortened value, or null when nothing (or a secret) was stored
	 */
	public static function decode(?string $json): mixed {
		if ($json === null || $json === '') {
			return null;
		}
		try {
			return json_decode($json, true, 8, JSON_THROW_ON_ERROR);
		} catch (\JsonException) {
			return null;
		}
	}

	private static function text(string $value): string {
		$clean = preg_replace('/[\x00-\x1f\x7f]+/u', ' ', $value) ?? preg_replace('/[\x00-\x1f\x7f]+/', ' ', $value) ?? '';
		return mb_strlen($clean) > self::MAX_TEXT ? mb_substr($clean, 0, self::MAX_TEXT - 1) . '…' : $clean;
	}

	private static function asText(mixed $value): string {
		return match (true) {
			is_bool($value) => $value ? 'true' : 'false',
			is_scalar($value) => (string)$value,
			default => json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR) ?: '',
		};
	}
}
