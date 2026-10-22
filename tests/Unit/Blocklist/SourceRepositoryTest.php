<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Blocklist;

use OCA\IntrusionDetection\Blocklist\BlocklistSource;
use OCA\IntrusionDetection\Blocklist\BuiltinSources;
use OCA\IntrusionDetection\Blocklist\ListFormat;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use Test\TestCase;

class SourceRepositoryTest extends TestCase {
	private string $stored = '[]';
	private SourceRepository $repository;

	protected function setUp(): void {
		parent::setUp();
		$settings = $this->createMock(AppSettings::class);
		$settings->method('blocklistSources')->willReturnCallback(fn (): string => $this->stored);
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturn('instance-secret');
		$this->repository = new SourceRepository($settings, new Fingerprinter($config, $this->createMock(ITimeFactory::class)));
	}

	public function testTheBuiltInListsArePreListedAndOff(): void {
		$all = $this->repository->all();
		$this->assertSame(array_keys(BuiltinSources::all()), array_keys($all));
		$this->assertSame([], $this->repository->enabled());
		$this->assertSame(BlocklistSource::PURPOSE_DENY, $all['spamhaus_drop_v4']->purpose);
		$this->assertSame(BlocklistSource::PURPOSE_HOSTING, $all['aws']->purpose);
		$this->assertSame(BlocklistSource::PURPOSE_TOR, $all['tor_exits']->purpose);
		$this->assertSame(3600, $all['tor_exits']->interval);
		$this->assertNull($all['aws']->mode, 'Attribute lists have no mode');
	}

	public function testStoredChoicesApplyToBuiltInListsButNotTheirAddress(): void {
		$this->stored = json_encode([
			['id' => 'spamhaus_drop_v4', 'enabled' => true, 'mode' => 'observe', 'url' => 'https://evil.example/x', 'purpose' => 'hosting'],
			['id' => 'tor_exits', 'enabled' => true, 'interval' => 7200],
		]);
		$drop = $this->repository->get('spamhaus_drop_v4');
		$this->assertNotNull($drop);
		$this->assertTrue($drop->enabled);
		$this->assertSame('observe', $drop->mode);
		$this->assertSame('https://www.spamhaus.org/drop/drop_v4.json', $drop->url);
		$this->assertSame(BlocklistSource::PURPOSE_DENY, $drop->purpose);
		$this->assertSame(7200, $this->repository->get('tor_exits')?->interval);
		$this->assertCount(2, $this->repository->enabled());
	}

	public function testCustomListsAreReadAndInvalidEntriesIgnored(): void {
		$this->stored = json_encode([
			['id' => 'office_block', 'url' => 'https://lists.example.org/block.txt', 'purpose' => 'deny', 'enabled' => true],
			['id' => 'hetzner', 'url' => 'https://lists.example.org/hetzner.txt', 'purpose' => 'hosting', 'mode' => 'protect', 'enabled' => true],
			['id' => 'plain_http', 'url' => 'http://lists.example.org/x.txt', 'purpose' => 'deny', 'enabled' => true],
			['id' => 'Bad-Id', 'url' => 'https://lists.example.org/x.txt', 'purpose' => 'deny'],
			['id' => 'no_purpose', 'url' => 'https://lists.example.org/x.txt'],
			['id' => 'bad_format', 'url' => 'https://lists.example.org/x.txt', 'purpose' => 'deny', 'format' => 'exe'],
			['id' => 'short_interval', 'url' => 'https://lists.example.org/x.txt', 'purpose' => 'tor', 'interval' => 5],
			'garbage',
		]);
		$all = $this->repository->all();
		$custom = $all['office_block'];
		$this->assertSame(BlocklistSource::MODE_OBSERVE, $custom->mode, 'Custom blocklists start in Observe');
		$this->assertSame(ListFormat::Cidr, $custom->format);
		$this->assertFalse($custom->builtin);
		$this->assertNull($all['hetzner']->mode);
		$this->assertArrayNotHasKey('plain_http', $all);
		$this->assertArrayNotHasKey('Bad-Id', $all);
		$this->assertArrayNotHasKey('no_purpose', $all);
		$this->assertArrayNotHasKey('bad_format', $all);
		$this->assertNull($all['short_interval']->interval, 'An out-of-range interval falls back to the default');
	}

	public function testBrokenJsonGivesTheBuiltInLists(): void {
		$this->stored = '{not json';
		$this->assertSame(array_keys(BuiltinSources::all()), array_keys($this->repository->all()));
	}

	public function testReferencesAreOpaqueStableAndCanBeLookedUp(): void {
		$reference = $this->repository->reference('spamhaus_drop_v4');
		$this->assertMatchesRegularExpression('/^LIST-[A-HJ-NP-Z2-9]{6}$/', $reference);
		$this->assertSame($reference, $this->repository->reference('spamhaus_drop_v4'));
		$this->assertNotSame($reference, $this->repository->reference('spamhaus_drop_v6'));
		$this->assertStringNotContainsStringIgnoringCase('spamhaus', $reference);
		$this->assertSame('spamhaus_drop_v4', $this->repository->findByReference(strtolower(str_replace('-', '', $reference)))?->id);
		$this->assertSame('spamhaus_drop_v4', $this->repository->findByReference(' ' . $reference)?->id);
		$this->assertNull($this->repository->findByReference('LIST-AAAAAA'));
	}
}
