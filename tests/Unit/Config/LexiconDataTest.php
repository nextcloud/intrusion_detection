<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Config;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Config\Lexicon;
use OCA\IntrusionDetection\Config\LexiconData;
use OCA\IntrusionDetection\Configure\LexiconDataBuilder;
use OCP\Config\Lexicon\Entry;
use OCP\Config\Lexicon\Preset;
use OCP\Config\ValueType;
use OCP\Server;
use Psr\Container\ContainerInterface;
use Test\TestCase;

/**
 * LexiconData is generated from the check registry and the global settings,
 * which stay the single source of truth. When this test fails, regenerate it:
 *
 *     IDS_WRITE_LEXICON_DATA=1 phpunit … --filter LexiconDataTest
 */
class LexiconDataTest extends TestCase {
	private LexiconDataBuilder $builder;

	protected function setUp(): void {
		parent::setUp();
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $class): object => Server::get($class));
		$this->builder = new LexiconDataBuilder(new CheckRegistry($container), new GlobalSettings());
		if (getenv('IDS_WRITE_LEXICON_DATA') === '1') {
			file_put_contents(dirname(__DIR__, 3) . '/lib/Config/LexiconData.php', $this->builder->source());
		}
	}

	public function testGlobalSettingsMatchTheirDefinitions(): void {
		$this->assertSame($this->builder->globals(), LexiconData::GLOBALS, 'LexiconData.php is out of date: run this test with IDS_WRITE_LEXICON_DATA=1');
	}

	public function testChecksMatchTheRegistry(): void {
		$this->assertSame($this->builder->checks(), LexiconData::CHECKS, 'LexiconData.php is out of date: run this test with IDS_WRITE_LEXICON_DATA=1');
		$this->assertSame(count(CheckRegistry::CHECKS), count(LexiconData::CHECKS));
	}

	public function testTheEntriesMatchTheDefinitions(): void {
		$this->assertSame($this->builder->entries(), LexiconData::ENTRIES, 'LexiconData.php is out of date: run this test with IDS_WRITE_LEXICON_DATA=1');
	}

	public function testTheLexiconHasAnEntryPerKeyWithItsTypeAndDefault(): void {
		$entries = (new Lexicon())->getAppConfigs();
		$this->assertCount(count(LexiconData::ENTRIES), $entries);
		foreach ($entries as $i => $entry) {
			[$key, $type, $default] = LexiconData::ENTRIES[$i];
			$this->assertSame($key, $entry->getKey());
			$this->assertSame($type, $entry->getValueType());
			$this->assertSame((new Entry($key, $type, $default))->getDefault(Preset::NONE), $entry->getDefault(Preset::NONE));
		}
		$this->assertSame(ValueType::BOOL, $entries[0]->getValueType(), GlobalSettings::ENABLED);
		$this->assertContains(Keys::mode('trap_url'), array_column(LexiconData::ENTRIES, 0));
	}

	public function testTheGeneratedSourceIsValidPhpWithTheSameData(): void {
		$source = $this->builder->source();
		$this->assertStringContainsString('final class LexiconData', $source);
		$file = tempnam(sys_get_temp_dir(), 'ids-lexicon');
		$this->assertIsString($file);
		$renamed = str_replace('final class LexiconData', 'final class LexiconDataCopy' . md5($source), $source);
		file_put_contents($file, $renamed);
		try {
			require $file;
		} finally {
			unlink($file);
		}
		$class = 'OCA\\IntrusionDetection\\Config\\LexiconDataCopy' . md5($source);
		$this->assertSame(LexiconData::CHECKS, constant($class . '::CHECKS'));
		$this->assertSame(LexiconData::GLOBALS, constant($class . '::GLOBALS'));
		$this->assertSame(LexiconData::ENTRIES, constant($class . '::ENTRIES'));
	}
}
