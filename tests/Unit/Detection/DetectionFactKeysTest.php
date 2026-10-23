<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Detection;

use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionAccounts;
use Test\TestCase;

/**
 * Deleting an account removes it only from the detections whose facts
 * name it under one of {@see DetectionAccounts::FACT_KEYS}. This test reads
 * the app's code for every fact key a detection can get and fails when a
 * key looks like it holds an account but is not one of those keys.
 *
 * Fact keys are the top-level keys of the arrays that become a detection's
 * facts: the `facts:` argument (of a detection draft or a permit), arrays
 * assigned or added to `$facts`, `$facts[...]` writes, the arrays that
 * methods named `...facts()` return, and those that the `toArray()` of a
 * facts class (`...Facts.php`) returns. Keys may be strings or class constants.
 */
class DetectionFactKeysTest extends TestCase {
	/** Words that make a key look like it holds an account */
	private const ACCOUNT_WORDS = [
		'uid', 'uids', 'user', 'users', 'account', 'accounts', 'actor', 'actors', 'owner', 'owners',
		'manager', 'managers', 'subject', 'requester', 'requested', 'approver', 'approved', 'decider',
		'decided', 'admin', 'admins', 'member', 'members', 'recipient', 'recipients', 'target', 'targets',
		'by', 'name', 'names', 'login', 'logins', 'person', 'people', 'initiator', 'granter', 'victim',
	];

	/** Keys that look like it but hold no account, and why */
	private const NOT_ACCOUNTS = [
		'actor_ip' => 'the address of the actor',
		'banTargets' => 'a count of addresses',
		'granter' => 'the address that approved a login request',
		'initiator' => 'the address that started a login request',
		'listNames' => 'the names of blocklists',
		'loginFailures' => 'a count of failed logins',
		'name' => 'a reserved name, which is no account',
		'names' => 'a count of login names',
		'providerName' => 'the name of a second-factor provider',
		'riskyLoginAt' => 'the time of a risky login',
		'riskyLoginPolicies' => 'the reasons a login was risky',
		'riskyLoginReason' => 'the reason a login was risky',
		'tokenName' => 'the name of an app password or session',
		'userHasEmail' => 'whether the account has an email address',
		'wantedBy' => 'the check that wanted to block an address',
		'alert_all_admins' => 'whether every administrator is told',
	];

	public function testEveryFactKeyThatHoldsAnAccountIsScrubbedWithTheAccount(): void {
		$keys = self::factKeys(dirname(__DIR__, 3) . '/lib');
		$unlisted = [];
		foreach ($keys as $key => $where) {
			if (self::looksLikeAccount($key) && !in_array($key, DetectionAccounts::FACT_KEYS, true) && !isset(self::NOT_ACCOUNTS[$key])) {
				$unlisted[] = $key . ' (' . implode(', ', array_unique($where)) . ')';
			}
		}
		$this->assertSame([], $unlisted, 'Add these to DetectionAccounts::FACT_KEYS, or to NOT_ACCOUNTS here with the reason');
	}

	public function testTheScanFindsTheFactsOfEveryKind(): void {
		$keys = self::factKeys(dirname(__DIR__, 3) . '/lib');
		// Draft and record arguments, $facts writes, permit facts, helper methods and constants.
		foreach (['targets', 'actor', 'requested_by', 'approved_by', 'owner', 'net', 'sessionTokenIds', 'alert_key', 'loweredLimits', 'excerpt', 'app', 'group', 'method'] as $key) {
			$this->assertArrayHasKey($key, $keys);
		}
		foreach (array_keys(self::NOT_ACCOUNTS) as $key) {
			$this->assertArrayHasKey($key, $keys, 'Only keys that are still used are excused');
		}
	}

	public function testFactsArePassedByName(): void {
		$positions = self::factsParameters();
		$this->assertArrayHasKey('DetectionDraft', $positions, 'The scan knows the draft\'s facts parameter');
		$this->assertArrayHasKey('AdminChanged', $positions, 'The scan knows the facts of an administration change');
		$positional = [];
		$files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(dirname(__DIR__, 3) . '/lib', \FilesystemIterator::SKIP_DOTS));
		foreach ($files as $file) {
			if ($file instanceof \SplFileInfo && $file->getExtension() === 'php') {
				array_push($positional, ...self::positionalFacts((string)$file->getRealPath(), $positions));
			}
		}
		$this->assertSame([], $positional, 'Pass facts as a named facts: argument, so that this test sees their keys');
	}

	public function testAnApprovedAdminAndASharedLinkNameTheirAccounts(): void {
		$granted = new Detection();
		$granted->setUid('new-admin');
		$granted->setExplanationData(['facts' => ['kind' => 'admin_granted', 'actor' => 'cron', 'requested_by' => 'asking-admin', 'approved_by' => 'second-admin', 'approval' => 7]]);
		$this->assertSame(['new-admin', 'cron', 'asking-admin', 'second-admin'], DetectionAccounts::of($granted));

		$share = new Detection();
		$share->setExplanationData(['facts' => ['owner' => 'sharer', 'managers' => ['sharer', 'co-owner'], 'share' => 'ocinternal:12']]);
		$this->assertSame(['sharer', 'co-owner'], DetectionAccounts::of($share));
	}

	/**
	 * Methods of the app with an array parameter named $facts, and its position.
	 * Constructors are listed under their class's short name.
	 *
	 * @return array<string, list<int>> method name => positions
	 */
	private static function factsParameters(): array {
		$classes = require dirname(__DIR__, 3) . '/composer/composer/autoload_classmap.php';
		$positions = [];
		foreach (array_keys($classes) as $class) {
			if (!str_starts_with($class, 'OCA\\IntrusionDetection\\') || str_contains($class, '\\Migration\\')) {
				continue;
			}
			$reflection = new \ReflectionClass($class);
			foreach ($reflection->getMethods() as $method) {
				// A private method's facts come from its own class, where the other parameters are looked at.
				if ($method->getDeclaringClass()->getName() !== $reflection->getName() || $method->isPrivate()) {
					continue;
				}
				foreach ($method->getParameters() as $parameter) {
					$type = $parameter->getType();
					$types = $type instanceof \ReflectionUnionType ? $type->getTypes() : [$type];
					if ($parameter->getName() === 'facts' && in_array('array', array_map(static fn (mixed $t): ?string => $t instanceof \ReflectionNamedType ? $t->getName() : null, $types), true)) {
						$name = $method->isConstructor() ? $reflection->getShortName() : $method->getName();
						$positions[$name][] = $parameter->getPosition();
					}
				}
			}
		}
		return array_map(static fn (array $p): array => array_values(array_unique($p)), $positions);
	}

	/**
	 * Calls that pass an array literal or $facts by position where a method
	 * of that name takes its facts.
	 *
	 * @param array<string, list<int>> $positions
	 * @return list<string> file:line of each such call
	 */
	private static function positionalFacts(string $path, array $positions): array {
		$tokens = array_values(array_filter(
			token_get_all((string)file_get_contents($path)),
			static fn (mixed $t): bool => !is_array($t) || !in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
		));
		$found = [];
		$count = count($tokens);
		for ($i = 1; $i < $count; $i++) {
			$name = $tokens[$i - 1];
			if ($tokens[$i] !== '(' || !is_array($name) || !in_array($name[0], [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED], true)) {
				continue;
			}
			$before = $tokens[$i - 2] ?? null;
			if (is_array($before) && $before[0] === T_FUNCTION) {
				continue;
			}
			$short = substr($name[1], (int)strrpos('\\' . $name[1], '\\'));
			if (!isset($positions[$short])) {
				continue;
			}
			// Walk the arguments: their index, whether named, and their first token.
			$depth = 0;
			$index = 0;
			$argStart = $i + 1;
			for ($j = $i + 1; $j < $count; $j++) {
				$text = is_array($tokens[$j]) ? $tokens[$j][1] : $tokens[$j];
				if (in_array($text, ['(', '[', '{'], true) || (is_array($tokens[$j]) && in_array($tokens[$j][0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true))) {
					$depth++;
					continue;
				}
				$end = in_array($text, [')', ']', '}'], true);
				if ($end && $depth > 0) {
					$depth--;
					continue;
				}
				if ($depth === 0 && ($text === ',' || $end)) {
					$first = $tokens[$argStart] ?? null;
					$named = is_array($first) && $first[0] === T_STRING && ($tokens[$argStart + 1] ?? null) === ':';
					$firstText = is_array($first) ? $first[1] : $first;
					if (!$named && in_array($index, $positions[$short], true) && ($firstText === '[' || $firstText === '$facts')) {
						$found[] = basename($path) . ':' . $name[2];
					}
					if ($end) {
						break;
					}
					$index++;
					$argStart = $j + 1;
				}
			}
		}
		return $found;
	}

	private static function looksLikeAccount(string $key): bool {
		$words = explode('_', strtolower((string)preg_replace('/(?<=[a-z0-9])(?=[A-Z])/', '_', $key)));
		return array_intersect($words, self::ACCOUNT_WORDS) !== [];
	}

	/**
	 * @return array<string, list<string>> fact key => where it is set (file:line)
	 */
	private static function factKeys(string $dir): array {
		$keys = [];
		$files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS));
		foreach ($files as $file) {
			if ($file instanceof \SplFileInfo && $file->getExtension() === 'php') {
				self::scanFile((string)$file->getRealPath(), $keys);
			}
		}
		ksort($keys);
		return $keys;
	}

	/**
	 * @param array<string, list<string>> $keys
	 */
	private static function scanFile(string $path, array &$keys): void {
		$tokens = array_values(array_filter(
			token_get_all((string)file_get_contents($path)),
			static fn (mixed $t): bool => !is_array($t) || !in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
		));
		$context = ['namespace' => '', 'class' => '', 'uses' => [], 'file' => basename($path)];
		$depth = 0;
		$factsMethodDepth = null;
		$count = count($tokens);
		for ($i = 0; $i < $count; $i++) {
			$token = $tokens[$i];
			$text = is_array($token) ? $token[1] : $token;
			if (is_array($token) && $token[0] === T_NAMESPACE) {
				$context['namespace'] = is_array($tokens[$i + 1]) ? $tokens[$i + 1][1] : '';
			} elseif (is_array($token) && $token[0] === T_USE && $depth === 0 && is_array($tokens[$i + 1]) && $tokens[$i + 1][0] === T_NAME_QUALIFIED) {
				$name = $tokens[$i + 1][1];
				$alias = is_array($tokens[$i + 2]) && $tokens[$i + 2][0] === T_AS ? $tokens[$i + 3][1] : substr($name, (int)strrpos($name, '\\') + 1);
				$context['uses'][$alias] = $name;
			} elseif (is_array($token) && in_array($token[0], [T_CLASS, T_INTERFACE, T_ENUM, T_TRAIT], true) && is_array($tokens[$i + 1]) && $tokens[$i + 1][0] === T_STRING && $context['class'] === '') {
				$context['class'] = $context['namespace'] . '\\' . $tokens[$i + 1][1];
			}

			if ($text === '{' || (is_array($token) && in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true))) {
				$depth++;
			} elseif ($text === '}') {
				$depth--;
				if ($factsMethodDepth !== null && $depth < $factsMethodDepth) {
					$factsMethodDepth = null;
				}
			}

			$line = $context['file'] . ':' . (is_array($token) ? $token[2] : '?');
			if (is_array($token) && $token[0] === T_FUNCTION && is_array($tokens[$i + 1])
				&& (preg_match('/(^f|F)acts$/', $tokens[$i + 1][1]) === 1 || ($tokens[$i + 1][1] === 'toArray' && str_ends_with($path, 'Facts.php')))) {
				$factsMethodDepth = $depth + 1;
			} elseif ($factsMethodDepth !== null && is_array($token) && $token[0] === T_RETURN) {
				self::keysOfExpression($tokens, $i + 1, $context, $line, $keys);
			} elseif (is_array($token) && $token[0] === T_STRING && $text === 'facts' && ($tokens[$i + 1] ?? null) === ':') {
				self::keysOfExpression($tokens, $i + 2, $context, $line, $keys);
			} elseif (is_array($token) && $token[0] === T_VARIABLE && $text === '$facts') {
				$next = $tokens[$i + 1] ?? null;
				$next = is_array($next) ? $next[1] : $next;
				if ($next === '=' || $next === '+=') {
					self::keysOfExpression($tokens, $i + 2, $context, $line, $keys);
				} elseif ($next === '[') {
					[$key, $end] = self::keyAt($tokens, $i + 2, $context);
					if ($key !== null && ($tokens[$end] ?? null) === ']') {
						$after = $tokens[$end + 1] ?? null;
						if (in_array(is_array($after) ? $after[1] : $after, ['=', '??=', '+=', '['], true)) {
							$keys[$key][] = $line;
						}
					}
				}
			}
		}
	}

	/**
	 * Collect the top-level keys of the array literals in an expression that
	 * starts at `$start` and ends at the first `,`, `;` or closing bracket
	 * of its own level.
	 *
	 * @param list<mixed> $tokens
	 * @param array{namespace: string, class: string, uses: array<string, string>, file: string} $context
	 * @param array<string, list<string>> $keys
	 */
	private static function keysOfExpression(array $tokens, int $start, array $context, string $line, array &$keys): void {
		$depth = 0;
		$count = count($tokens);
		for ($i = $start; $i < $count; $i++) {
			$text = is_array($tokens[$i]) ? $tokens[$i][1] : $tokens[$i];
			if ($text === '(' && ($tokens[$i + 1] ?? null) === '[') {
				// An array literal as a call's first argument, as in FactValues::recorded([...]).
				continue;
			}
			if ($text === '[' || $text === '(') {
				$depth++;
				continue;
			}
			if ($text === ']' || $text === ')') {
				if ($depth === 0) {
					return;
				}
				$depth--;
				continue;
			}
			if ($depth === 0 && ($text === ',' || $text === ';')) {
				return;
			}
			if ($depth === 1) {
				[$key, $end] = self::keyAt($tokens, $i, $context);
				if ($key !== null && is_array($tokens[$end] ?? null) && $tokens[$end][0] === T_DOUBLE_ARROW) {
					$keys[$key][] = $line;
					$i = $end;
				}
			}
		}
	}

	/**
	 * A string literal or class constant at `$i`, and the index after it.
	 *
	 * @param list<mixed> $tokens
	 * @param array{namespace: string, class: string, uses: array<string, string>, file: string} $context
	 * @return array{0: ?string, 1: int}
	 */
	private static function keyAt(array $tokens, int $i, array $context): array {
		$token = $tokens[$i] ?? null;
		if (is_array($token) && $token[0] === T_CONSTANT_ENCAPSED_STRING) {
			return [substr($token[1], 1, -1), $i + 1];
		}
		if (is_array($token) && in_array($token[0], [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED], true)
			&& is_array($tokens[$i + 1] ?? null) && $tokens[$i + 1][0] === T_DOUBLE_COLON
			&& is_array($tokens[$i + 2] ?? null) && $tokens[$i + 2][0] === T_STRING) {
			$class = match (true) {
				$token[1] === 'self' || $token[1] === 'static' => $context['class'],
				str_starts_with($token[1], '\\') => substr($token[1], 1),
				default => $context['uses'][$token[1]] ?? $context['namespace'] . '\\' . $token[1],
			};
			$value = defined($class . '::' . $tokens[$i + 2][1]) ? constant($class . '::' . $tokens[$i + 2][1]) : null;
			return [is_string($value) ? $value : null, $i + 3];
		}
		return [null, $i + 1];
	}
}
