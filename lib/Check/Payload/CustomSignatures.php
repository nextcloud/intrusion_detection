<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Payload;

use OCA\IntrusionDetection\Check\InvalidParamException;

/**
 * Signatures an admin adds. Each entry is a regular expression without
 * delimiters, optionally prefixed with a weight from 1 to 9 and a colon
 * (`2:union\s+distinct`); without one the weight is 3. It runs
 * case-insensitively on the normalised value, like the built-in ones.
 *
 * Validation is what keeps a custom signature from becoming a denial of
 * service: it must compile, may not match an empty value, is length-limited,
 * and when it is saved it is run against long adversarial input with a low
 * backtracking limit and a time budget. A slow one is refused.
 */
class CustomSignatures {
	public const MAX_LENGTH = 300;
	public const MAX_ITEMS = 50;
	public const DEFAULT_WEIGHT = 3;
	/** PCRE backtracking limit for custom signatures, at save time and when matching */
	public const BACKTRACK_LIMIT = 100000;
	/** Time all adversarial inputs together may take for one signature at save time */
	public const TIME_BUDGET_MS = 50;
	/** Length of each adversarial input at save time */
	public const ADVERSARIAL_LENGTH = 16384;
	public const ID_PREFIX = 'custom_';

	public const PROBLEM_TOO_LONG = 'too_long';
	public const PROBLEM_INVALID = 'does_not_compile';
	public const PROBLEM_MATCHES_EVERYTHING = 'matches_everything';
	public const PROBLEM_TOO_SLOW = 'too_slow';

	/** Delimiter that cannot occur in an entry: entries may not contain control characters */
	private const DELIMITER = "\x01";

	/**
	 * The signature for an entry, or null for one that cannot be used (it
	 * is then skipped: a broken custom signature must never break requests).
	 */
	public function parse(string $entry): ?Signature {
		[$weight, $body] = self::split($entry);
		if ($body === '' || strlen($entry) > self::MAX_LENGTH || preg_match('~[\x00-\x1f\x7f]~', $entry) === 1) {
			return null;
		}
		$pattern = self::DELIMITER . $body . self::DELIMITER . 'i';
		if (@preg_match($pattern, '') !== 0) {
			return null;
		}
		return new Signature(self::idFor($entry), $pattern, $weight, Signature::SCOPE_ANY, false, true);
	}

	public static function idFor(string $entry): string {
		return self::ID_PREFIX . substr(hash('sha256', $entry), 0, 8);
	}

	/**
	 * Why an entry cannot be used, or null when it can.
	 *
	 * @param bool $thorough also run the timing test (when saving; reads only check that it compiles)
	 * @return self::PROBLEM_*|null
	 */
	public function problem(string $entry, bool $thorough = true): ?string {
		if (strlen($entry) > self::MAX_LENGTH) {
			return self::PROBLEM_TOO_LONG;
		}
		[, $body] = self::split($entry);
		$pattern = self::DELIMITER . $body . self::DELIMITER . 'i';
		$result = $body === '' || preg_match('~[\x00-\x1f\x7f]~', $entry) === 1 ? false : @preg_match($pattern, '');
		if ($result === false) {
			return self::PROBLEM_INVALID;
		}
		if ($result === 1) {
			return self::PROBLEM_MATCHES_EVERYTHING;
		}
		if ($thorough && !$this->isFast($pattern, $body)) {
			return self::PROBLEM_TOO_SLOW;
		}
		return null;
	}

	/**
	 * Validate a whole list as the admin API and occ save it.
	 *
	 * @param list<string> $entries
	 * @throws InvalidParamException
	 */
	public function validate(array $entries, string $param = 'custom_signatures'): void {
		if (count($entries) > self::MAX_ITEMS) {
			throw new InvalidParamException('too_many_items', ['param' => $param, 'max' => self::MAX_ITEMS]);
		}
		foreach ($entries as $entry) {
			$problem = $this->problem($entry);
			if ($problem !== null) {
				throw new InvalidParamException('invalid_pattern', ['param' => $param, 'item' => mb_substr($entry, 0, 60), 'why' => $problem]);
			}
		}
	}

	/**
	 * Run a pattern with the same low backtracking limit as when matching.
	 *
	 * @return int|false 1 or 0, or false when the pattern failed (counts as no match)
	 */
	public static function run(string $pattern, string $subject, ?array &$match = null): int|false {
		$previous = ini_get('pcre.backtrack_limit');
		ini_set('pcre.backtrack_limit', (string)self::BACKTRACK_LIMIT);
		try {
			return @preg_match($pattern, $subject, $match, PREG_OFFSET_CAPTURE);
		} finally {
			ini_set('pcre.backtrack_limit', $previous === false ? '1000000' : $previous);
		}
	}

	private function isFast(string $pattern, string $body): bool {
		$start = hrtime(true);
		foreach (self::adversarialInputs($body) as $input) {
			if (self::run($pattern, $input) === false) {
				return false;
			}
			if ((hrtime(true) - $start) / 1e6 > self::TIME_BUDGET_MS) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Long inputs that make badly written patterns backtrack: long runs of
	 * single characters, of SQL-like fragments and of the pattern's own
	 * characters. Every printable character comes once before and once after
	 * the run, so PCRE cannot skip the work by noticing that a required
	 * character is missing; the input ends with one that rarely completes a match.
	 *
	 * @return list<string>
	 */
	private static function adversarialInputs(string $body): array {
		$printable = implode('', array_map('chr', range(0x20, 0x7e)));
		$fragments = ['a', '1', 'a ', "' or 1=1 ", 'select ', '%27(),;-=/*'];
		$own = array_values(array_unique(str_split(preg_replace('~[^\x21-\x7e]~', '', $body) ?? '')));
		if ($own !== []) {
			$fragments[] = implode('', array_slice($own, 0, 32));
			foreach (array_slice($own, 0, 8) as $char) {
				$fragments[] = $char;
			}
		}
		$inputs = [];
		foreach (array_unique($fragments) as $fragment) {
			$inputs[] = $printable . substr(str_repeat($fragment, intdiv(self::ADVERSARIAL_LENGTH, strlen($fragment)) + 1), 0, self::ADVERSARIAL_LENGTH) . $printable . "\x02";
		}
		return $inputs;
	}

	/**
	 * @return array{0: int, 1: string} weight and pattern body
	 */
	private static function split(string $entry): array {
		if (preg_match('~^([1-9]):(.+)$~sD', $entry, $m) === 1) {
			return [(int)$m[1], $m[2]];
		}
		return [self::DEFAULT_WEIGHT, $entry];
	}
}
