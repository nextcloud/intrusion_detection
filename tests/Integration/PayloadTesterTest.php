<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\Checks\InjectionProbe\InjectionProbe;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PayloadTester;
use OCA\IntrusionDetection\Command\Payload\Test;
use OCA\IntrusionDetection\Definition\Mode;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\Console\Tester\CommandTester;

#[Group('DB')]
class PayloadTesterTest extends IntegrationTestCase {
	private PayloadTester $tester;
	private IL10N $l;

	protected function setUp(): void {
		parent::setUp();
		$this->tester = Server::get(PayloadTester::class);
		$this->l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
	}

	public function testAUrlShowsEveryStep(): void {
		$result = $this->tester->test('https://cloud.example.com/index.php/apps/foo?page=2&data=JyBPUiAnMSc9JzE=&password=secret%27--', $this->l);
		$this->assertSame('url', $result['kind']);
		$this->assertTrue($result['prefilter']);
		$this->assertTrue($result['fires']);
		$this->assertSame(3, $result['minWeight']);
		$this->assertSame(['anonymous' => 'protect', 'authenticated' => 'observe'], $result['modes']);

		$byName = array_column($result['values'], null, 'name');
		$data = $byName['data'];
		$this->assertTrue($data['fires']);
		$this->assertSame(["' OR '1'='1"], $data['decoded']);
		$this->assertSame('base64', $data['forms'][1]['encoding']);
		$this->assertSame('sql_tautology', $data['forms'][1]['matches'][0]['id']);
		$this->assertSame(3, $data['forms'][1]['matches'][0]['weight']);
		$this->assertNotSame('', $data['forms'][1]['matches'][0]['description']);
		$this->assertFalse($byName['page']['fires']);

		$this->assertSame('secret', $byName['password']['skipped']);
		$this->assertArrayNotHasKey('normalised', $byName['password'], 'A password field is not shown');
		$this->assertStringNotContainsString('secret%27', json_encode($result) ?: '');
	}

	public function testASingleValue(): void {
		$result = $this->tester->test("1' UNION SELECT password FROM oc_users --", $this->l);
		$this->assertSame('value', $result['kind']);
		$this->assertTrue($result['fires']);
		$this->assertSame("1' union select password from oc_users --", $result['values'][0]['normalised']);

		$harmless = $this->tester->test("O'Brien", $this->l);
		$this->assertFalse($harmless['fires']);
		$this->assertTrue($harmless['prefilter'], 'A quote is enough for a closer look');
	}

	public function testFilePathsAndSettingsAreReflected(): void {
		$result = $this->tester->test("/remote.php/dav/files/alice/Bob's union select.txt", $this->l);
		$this->assertTrue($result['pathExcluded']);
		$this->assertFalse($result['fires']);
		$this->assertSame([], $result['values']);

		$this->settingsEditor()->setMode(InjectionProbe::ID, Mode::Observe);
		$this->settingsEditor()->setParam(InjectionProbe::ID, InjectionProbe::PARAM_MIN_WEIGHT, 7);
		$result = $this->tester->test('/x?id=1%20UNION%20SELECT%201', $this->l);
		$this->assertFalse($result['fires']);
		$this->assertSame(7, $result['minWeight']);
		$this->assertSame('observe', $result['modes']['anonymous']);
	}

	public function testTheCommand(): void {
		$command = new CommandTester(new Test($this->tester, $this->l));
		$command->execute(['url-or-value' => '/index.php/apps/foo?d=VU5JT04gU0VMRUNUIHBhc3N3b3JkIEZST00gb2NfdXNlcnM&name=x']);
		$output = $command->getDisplay();
		$this->assertSame(0, $command->getStatusCode());
		$this->assertStringContainsString('query parameter d', $output);
		$this->assertStringContainsString('decoded from base64: union select password from oc_users', $output);
		$this->assertStringContainsString('sql_union_select (weight 3)', $output);
		$this->assertStringContainsString('not inspected: excluded free-text field', $output);
		$this->assertStringContainsString('Would fire.', $output);

		$command->execute(['url-or-value' => 'hello', '--output' => 'json']);
		$json = json_decode($command->getDisplay(), true);
		$this->assertFalse($json['fires']);
		$this->assertFalse($json['prefilter']);
	}
}
