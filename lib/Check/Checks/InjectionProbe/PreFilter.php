<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\InjectionProbe;

/**
 * The cheap test every request goes through: does the path, the query string
 * or a form field contain anything a signature could match at all?
 *
 * One case-insensitive pass looks for trigger characters and words, in plain
 * and percent-encoded form, and a second for whole values that are base64
 * text. Most requests contain neither and are done here.
 *
 * Every signature contains at least one of these triggers, so a value that
 * passes this test unseen cannot reach the minimum weight of 2. Encoded
 * letters and digits (`%55NION`) are triggers too: normal clients never
 * encode them, so they mean someone hides a word.
 */
final class PreFilter {
	/** No more than this much of the path, query and each form field is scanned */
	public const MAX_SCAN = 65536;

	/** Trigger characters and their percent-encoded forms, run on the lower-cased text */
	private const TRIGGER_CHARACTERS = '~[\'"`<;]|%(?:2[257]|3[0-9bc]|60|23|4[1-9a-f]|5[0-9a]|6[1-9a-f]|7[0-9a]|40%40)|--|/\*|0x|\.\.(?:/|\\\\|%2f|%5c)|(?:\$|%24)(?:\{|%7b)|@@~';
	/** Trigger words, run on the lower-cased text; grouped by first letters, which PCRE matches faster */
	private const TRIGGER_WORDS = '~u(?:nion|pdatexml|tl_inaddr)|s(?:elect|leep|qlite_|ys\.?objects|p_(?:executesql|oacreate|configure))'
		. '|benchmark|waitfor|information_schema|pg_(?:catalog|shadow)|mysql\.user|extractvalue|load_file|ctxsys|(?:out|dump)file|xp_cmdshell'
		. '|etc(?:/|%2f)(?:passwd|shadow)'
		. '|(?:or|and)(?:\+|%20|%09|%0a|%0d|\s)++\d{1,10}(?:\+|%20|\s)*+(?:=|%3d)~';

	/**
	 * A whole query value or path segment made of base64 characters (also
	 * percent-encoded ones) with optional padding. Only whole values are ever
	 * decoded, so only they can hide a payload.
	 */
	private const QUERY_VALUE = '~=((?:[A-Za-z0-9+/_-]|%2[bBdDfF]|%5[fF]|%20){14,}(?:=|%3[dD]){0,2})(?=&|$)~D';
	private const PATH_SEGMENT = '~/((?:[A-Za-z0-9+_-]|%2[bBdD]|%5[fF]){14,}(?:=|%3[dD]){0,2})(?=/|$)~D';

	public static function hit(RequestParts $parts): bool {
		$path = self::limit($parts->path);
		$query = self::limit($parts->query);
		// One pass over path and query together; `?` is no part of any trigger.
		if (self::triggers($path . '?' . $query)) {
			return true;
		}
		// The inspector splits the decoded path at every slash, encoded ones too.
		if ($path !== '' && (stripos($path, '%2f') !== false || self::hasBase64Text($path, self::PATH_SEGMENT))) {
			return true;
		}
		if ($query !== '' && self::hasBase64Text($query, self::QUERY_VALUE)) {
			return true;
		}
		return $parts->post !== [] && self::scanFields($parts->post, 0);
	}

	/**
	 * @param array<array-key, mixed> $fields
	 */
	private static function scanFields(array $fields, int $depth): bool {
		foreach ($fields as $value) {
			if (is_string($value)) {
				$value = self::limit($value);
				if (self::triggers($value) || self::isBase64Text(Base64Inspector::formCandidate($value))) {
					return true;
				}
			} elseif (is_array($value) && $depth < 4 && self::scanFields($value, $depth + 1)) {
				return true;
			}
		}
		return false;
	}

	private static function limit(string $subject): string {
		return strlen($subject) > self::MAX_SCAN ? substr($subject, 0, self::MAX_SCAN) : $subject;
	}

	private static function triggers(string $subject): bool {
		$lower = strtolower($subject);
		// A pcre failure (false) counts as a hit, so the full inspection decides.
		return preg_match(self::TRIGGER_CHARACTERS, $lower) !== 0 || preg_match(self::TRIGGER_WORDS, $lower) !== 0;
	}

	private static function hasBase64Text(string $subject, string $pattern): bool {
		$offset = 0;
		while (preg_match($pattern, $subject, $m, PREG_OFFSET_CAPTURE, $offset) === 1) {
			if (self::isBase64Text(Normalizer::urlDecode($m[1][0]))) {
				return true;
			}
			$offset = $m[1][1] + strlen($m[1][0]);
		}
		return false;
	}

	/**
	 * The same test the matcher applies to the first level: strict, canonical
	 * base64 that decodes to text.
	 */
	private static function isBase64Text(string $value): bool {
		return strlen($value) >= Base64Inspector::MIN_LENGTH && (new Base64Inspector())->decodeOnce($value) !== null;
	}
}
