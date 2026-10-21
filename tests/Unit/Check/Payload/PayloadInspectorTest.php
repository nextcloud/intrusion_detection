<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check\Payload;

use OCA\IntrusionDetection\Check\Checks\InjectionProbe;
use OCA\IntrusionDetection\Check\Payload\Base64Inspector;
use OCA\IntrusionDetection\Check\Payload\FormMatch;
use OCA\IntrusionDetection\Check\Payload\InspectedValue;
use OCA\IntrusionDetection\Check\Payload\Normalizer;
use OCA\IntrusionDetection\Check\Payload\PayloadHit;
use OCA\IntrusionDetection\Check\Payload\PayloadInspector;
use OCA\IntrusionDetection\Check\Payload\PayloadMatcher;
use OCA\IntrusionDetection\Check\Payload\PayloadRules;
use OCA\IntrusionDetection\Check\Payload\RequestParts;
use Test\TestCase;

class PayloadInspectorTest extends TestCase {
	private PayloadInspector $inspector;
	private PayloadRules $rules;

	protected function setUp(): void {
		parent::setUp();
		$this->inspector = new PayloadInspector(new PayloadMatcher(new Normalizer(), new Base64Inspector()));
		$this->rules = PayloadRules::build(3, 8192, [], [], InjectionProbe::DEFAULT_EXCLUDED);
	}

	private function inspect(string $uri, array $post = [], ?PayloadRules $rules = null): ?PayloadHit {
		return $this->inspector->inspect(RequestParts::fromUri($uri, '/index.php', $post), $rules ?? $this->rules);
	}

	public function testReportsTheParameterTheSignaturesAndTheExcerpt(): void {
		$hit = $this->inspect('/index.php/apps/foo?page=2&id=1%27%20UNION%20SELECT%20password%20FROM%20oc_users--');
		$this->assertNotNull($hit);
		$this->assertSame(PayloadHit::LOCATION_QUERY, $hit->location);
		$this->assertSame('id', $hit->param);
		$this->assertArrayHasKey('sql_union_select', $hit->signatures);
		$this->assertSame(array_sum($hit->signatures), $hit->weight);
		$this->assertSame(FormMatch::ENCODING_NONE, $hit->encoding);
		$this->assertSame("1' union select password from oc_users--", $hit->excerpt);
		$this->assertSame([], $hit->otherParams);
	}

	public function testTheStrongestPartIsReportedAndTheOthersNamed(): void {
		$hit = $this->inspect('/index.php/apps/foo?a=1%20UNION%20SELECT%201&b=1%27%20OR%20%271%27=%271%27%20UNION%20SELECT%201--', ['c' => "x' or 1=1"]);
		$this->assertNotNull($hit);
		$this->assertSame('b', $hit->param);
		$this->assertSame(['a', 'c'], $hit->otherParams);
	}

	public function testSecretParametersAreNeverInspected(): void {
		foreach (['password', 'new_password', 'passwd', 'clientSecret', 'requesttoken', 'shareToken', 'user[password]', 'PASSWORD'] as $name) {
			$this->assertNull($this->inspect('/index.php/apps/foo?' . rawurlencode($name) . '=1%27%20UNION%20SELECT%201--'), $name);
			$this->assertNull($this->inspect('/index.php/apps/foo', [$name => "1' UNION SELECT 1--"]), $name);
		}
		$this->assertNull($this->inspect('/index.php/apps/foo', ['user' => ['password' => "1' UNION SELECT 1--"]]));
	}

	public function testFreeTextParametersAreExcluded(): void {
		$this->assertNull($this->inspect('/index.php/apps/foo?comment=1%20UNION%20SELECT%201'));
		$this->assertNull($this->inspect('/index.php/apps/foo?files[]=1%20UNION%20SELECT%201'));
		$this->assertNotNull($this->inspect('/index.php/apps/foo?q=1%20UNION%20SELECT%201'), 'q is inspected outside search routes');
		$this->assertNull($this->inspector->inspect(RequestParts::fromUri('/ocs/v2.php/search/providers/x/search?q=1%20UNION%20SELECT%201', '/ocs/v2.php'), $this->rules));
		$custom = PayloadRules::build(3, 8192, [], [], ['legacy_sql']);
		$this->assertNull($this->inspect('/index.php/apps/foo?legacy_sql=1%20UNION%20SELECT%201', [], $custom));
		$this->assertNotNull($this->inspect('/index.php/apps/foo?comment=1%20UNION%20SELECT%201', [], $custom), 'The list is configurable');
	}

	public function testOnlyTheByteBudgetIsInspected(): void {
		$rules = PayloadRules::build(3, 1024, [], [], []);
		$this->assertNotNull($this->inspect('/index.php/apps/foo?a=' . str_repeat('x', 900) . '&id=1%20UNION%20SELECT%201', [], $rules));
		$this->assertNull($this->inspect('/index.php/apps/foo?a=' . str_repeat('x', 1100) . '&id=1%20UNION%20SELECT%201', [], $rules));
		$this->assertNull($this->inspect('/index.php/apps/foo?a=' . str_repeat('x', 1020) . '1%20UNION%20SELECT%201', [], $rules), 'A value is cut at the budget');

		$values = $this->inspector->values(RequestParts::fromUri('/index.php/x?a=' . str_repeat('x', 1100) . '&b=1', '/index.php'), $rules);
		$this->assertTrue($values[1]->truncated);
		$this->assertSame(InspectedValue::SKIPPED_BUDGET, $values[2]->skipped);
	}

	public function testExcludedValuesDoNotUseTheBudget(): void {
		$rules = PayloadRules::build(3, 1024, [], [], []);
		$this->assertNotNull($this->inspect('/index.php/apps/foo?password=' . str_repeat('x', 5000) . '&id=1%20UNION%20SELECT%201', [], $rules));
	}

	public function testTheNumberOfFieldsIsCapped(): void {
		$query = str_repeat('a=1&', PayloadInspector::MAX_FIELDS) . 'id=1%20UNION%20SELECT%201';
		$this->assertNull($this->inspect('/index.php/apps/foo?' . $query, [], PayloadRules::build(3, 65536, [], [], [])));
	}

	public function testTokensInThePathAreMaskedInTheExcerpt(): void {
		$hit = $this->inspect('/index.php/s/AbCdEfGhIjKlMnO/download?x=1&path=/&id=1');
		$this->assertNull($hit);
		$hit = $this->inspect('/index.php/s/AbCdEfGhIjKlMnO/1%27%20OR%20%271%27=%271');
		$this->assertNotNull($hit);
		$this->assertSame(PayloadHit::LOCATION_PATH, $hit->location);
		$this->assertStringNotContainsStringIgnoringCase('AbCdEfGhIjKlMnO', $hit->excerpt);
		$this->assertStringContainsString('/s/***************/', $hit->excerpt);
		$this->assertStringContainsString("1' or '1'='1", $hit->excerpt);
	}

	public function testBase64InAPathSegment(): void {
		$hit = $this->inspect('/index.php/apps/foo/' . rtrim(strtr(base64_encode("' OR '1'='1 --"), '+/', '-_'), '='));
		$this->assertNotNull($hit);
		$this->assertSame(FormMatch::ENCODING_BASE64, $hit->encoding);
	}

	public function testParameterNamesAreCleaned(): void {
		$hit = $this->inspect('/index.php/apps/foo?' . rawurlencode("i\x01d" . str_repeat('x', 200)) . '=1%20UNION%20SELECT%201');
		$this->assertNotNull($hit);
		$this->assertSame(PayloadInspector::MAX_NAME_LENGTH, mb_strlen($hit->param));
		$this->assertStringStartsWith('idxx', $hit->param);
	}
}
