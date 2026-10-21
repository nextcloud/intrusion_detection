<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check\Payload;

use OCA\IntrusionDetection\Check\Payload\Base64Inspector;
use OCA\IntrusionDetection\Check\Payload\Normalizer;
use OCA\IntrusionDetection\Check\Payload\PayloadMatcher;
use OCA\IntrusionDetection\Check\Payload\PayloadRules;
use OCA\IntrusionDetection\Check\Payload\Signature;
use OCA\IntrusionDetection\Check\Payload\Signatures;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class SignaturesTest extends TestCase {
	/** Upper bound for one signature on one 100 KB input; linear patterns need well under 1 ms */
	private const MAX_MS_PER_RUN = 25;

	public function testIdsAreUniqueStableAndDescribed(): void {
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$ids = array_map(static fn (Signature $s): string => $s->id, Signatures::builtIn());
		$this->assertSame($ids, array_values(array_unique($ids)));
		$this->assertSame($ids, Signatures::ids());
		foreach (Signatures::builtIn() as $signature) {
			$this->assertMatchesRegularExpression('/^(sql|payload)_[a-z0-9_]+$/', $signature->id);
			$this->assertNotSame(Signatures::describe('unknown', $l), Signatures::describe($signature->id, $l), $signature->id . ' has no description');
			$this->assertGreaterThanOrEqual(1, $signature->weight);
			$this->assertLessThanOrEqual(3, $signature->weight);
		}
		$this->assertCount(count($ids), Signatures::catalog($l));
	}

	public function testEveryPatternCompilesAndNeverMatchesEmptyText(): void {
		foreach (Signatures::builtIn() as $signature) {
			$this->assertSame(0, preg_match($signature->pattern, ''), $signature->id);
			$this->assertSame(0, preg_match($signature->pattern, ' '), $signature->id);
		}
	}

	public function testNoPatternHasNestedQuantifiers(): void {
		foreach (Signatures::builtIn() as $signature) {
			// A quantified group that itself contains an unbounded quantifier is the shape of catastrophic backtracking.
			$this->assertDoesNotMatchRegularExpression('/\((?:[^()\\\\]|\\\\.)*[*+](?:[^()\\\\]|\\\\.)*\)[*+{]/', $signature->pattern, $signature->id);
		}
	}

	/**
	 * Long inputs built to make patterns backtrack: repeated fragments of
	 * what the signatures look for, never completing a match.
	 *
	 * @return array<string, array{string}>
	 */
	public static function adversarial(): array {
		$size = 100 * 1024;
		$inputs = [
			'one letter' => 'a',
			'digits' => '1',
			'spaces' => ' ',
			'quotes' => "'",
			'quote or' => "' or ",
			'quote or digits' => "' or 1",
			'or digits' => 'or 1 ',
			'select' => 'select ',
			'union' => 'union ',
			'union all' => 'union all ',
			'sleep' => 'sleep( ',
			'hex' => '0x',
			'hex digits' => '0x1234567',
			'comments' => '/*',
			'dollar brace' => '${',
			'wget' => 'wget http://x',
			'curl flag' => 'curl -s https://',
			'traversal' => '../',
			'at at' => '@@',
			'semicolons' => '; ',
			'angle' => '<scrip',
			'mixed punctuation' => "'\"`()=;-#/*<>|&",
		];
		$result = [];
		foreach ($inputs as $name => $fragment) {
			$result[$name] = [substr(str_repeat($fragment, intdiv($size, strlen($fragment)) + 1), 0, $size)];
		}
		return $result;
	}

	#[DataProvider('adversarial')]
	public function testNoSignatureBacktracksCatastrophically(string $input): void {
		foreach (Signatures::builtIn() as $signature) {
			$start = hrtime(true);
			$result = preg_match($signature->pattern, $input);
			$ms = (hrtime(true) - $start) / 1e6;
			$this->assertNotFalse($result, $signature->id . ' failed: ' . preg_last_error_msg());
			$this->assertLessThan(self::MAX_MS_PER_RUN, $ms, $signature->id . ' took ' . round($ms, 2) . ' ms');
		}
	}

	#[DataProvider('adversarial')]
	public function testTheWholeMatcherStaysFastOnLongInput(string $input): void {
		$matcher = new PayloadMatcher(new Normalizer(), new Base64Inspector());
		$rules = PayloadRules::build(3, 8192, [], [], []);
		$start = hrtime(true);
		$matcher->analyse($input, $rules);
		$ms = (hrtime(true) - $start) / 1e6;
		$this->assertLessThan(100, $ms, 'The matcher took ' . round($ms, 2) . ' ms on 100 KB');
	}
}
