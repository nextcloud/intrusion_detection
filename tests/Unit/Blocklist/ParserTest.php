<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Blocklist;

use OCA\IntrusionDetection\Blocklist\BuiltinSources;
use OCA\IntrusionDetection\Blocklist\ListFormat;
use OCA\IntrusionDetection\Blocklist\Parser\ListFormatException;
use OCA\IntrusionDetection\Blocklist\Parser\ListTooLongException;
use OCA\IntrusionDetection\Blocklist\Parser\ParsedList;
use OCA\IntrusionDetection\Net\RangeCodec;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

/**
 * Each parser on a small fixture in the provider's real format (with
 * documentation address ranges instead of real list data).
 */
class ParserTest extends TestCase {
	/**
	 * @return array<string, array{ListFormat, string, list<string>, int}>
	 */
	public static function fixtures(): array {
		return [
			'Spamhaus DROP IPv4' => [ListFormat::SpamhausJson, 'spamhaus_drop_v4.json', ['192.0.2.0/25', '192.0.2.128/25', '198.51.100.0/24', '203.0.113.64/26'], 0],
			'Spamhaus DROP IPv6' => [ListFormat::SpamhausJson, 'spamhaus_drop_v6.json', ['2001:db8:100::/48', '2001:db8:200::/40'], 0],
			'FireHOL level 1' => [ListFormat::Cidr, 'firehol_level1.netset', ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.9/32'], 7],
			'AWS' => [ListFormat::AwsJson, 'aws_ip_ranges.json', ['198.51.100.0/24', '198.51.100.0/25', '203.0.113.4/32', '2001:db8:a000::/40'], 0],
			'Google Cloud' => [ListFormat::GoogleJson, 'google_cloud.json', ['192.0.2.0/24', '203.0.113.0/26', '2001:db8:1900::/44'], 0],
			'Oracle Cloud' => [ListFormat::OracleJson, 'oracle_public_ip_ranges.json', ['192.0.2.0/27', '192.0.2.32/27', '198.51.100.128/25'], 0],
			'DigitalOcean' => [ListFormat::GeofeedCsv, 'digitalocean.csv', ['192.0.2.0/24', '198.51.100.0/23', '2001:db8:d0::/48'], 0],
			'Tor exit list' => [ListFormat::Cidr, 'tor_exits.txt', ['192.0.2.10/32', '192.0.2.11/32', '198.51.100.25/32', '2001:db8::7/128'], 0],
			'custom list' => [ListFormat::Cidr, 'custom.txt', ['192.0.2.0/24', '198.51.100.7/32', '2001:db8:42::/48'], 0],
		];
	}

	/**
	 * @param list<string> $expected
	 */
	#[DataProvider('fixtures')]
	public function testParsesTheFixture(ListFormat $format, string $file, array $expected, int $skipped): void {
		$parsed = $format->parser()->parse($this->fixture($file));
		$this->assertSame(0, $parsed->malformed);
		$this->assertSame($skipped, $parsed->skipped);
		$this->assertSame(count($expected) + $skipped, $parsed->entries);
		$this->assertSame($expected, self::ranges($parsed));
	}

	public function testEveryBuiltInListHasAFormatWithAFixture(): void {
		$tested = array_map(static fn (array $f): ListFormat => $f[0], self::fixtures());
		foreach (BuiltinSources::all() as $source) {
			$this->assertContains($source->format, $tested, $source->id);
			$this->assertStringStartsWith('https://', $source->url);
			$this->assertFalse($source->enabled, $source->id . ' must be off by default');
		}
	}

	public function testFireholBogonsAreLeftOut(): void {
		$parsed = ListFormat::Cidr->parser()->parse($this->fixture('firehol_level1.netset'));
		foreach (self::ranges($parsed) as $cidr) {
			$this->assertStringStartsNotWith('10.', $cidr);
			$this->assertStringStartsNotWith('192.168.', $cidr);
			$this->assertStringStartsNotWith('127.', $cidr);
		}
	}

	public function testPlainTextCountsMalformedLines(): void {
		$parsed = ListFormat::Cidr->parser()->parse("192.0.2.0/24\nnot-a-range\n198.51.100.0/24 extra words\n\n# comment\n203.0.113.0/24\r\n");
		$this->assertSame(2, $parsed->malformed);
		$this->assertSame(2, $parsed->entries);
		$this->assertEqualsWithDelta(0.5, $parsed->malformedShare(), 0.0001);
	}

	public function testAnHtmlErrorPageIsAllMalformed(): void {
		$parsed = ListFormat::Cidr->parser()->parse("<!DOCTYPE html>\n<html><head><title>Rate limited</title></head>\n<body>Try again later</body></html>\n");
		$this->assertSame(0, $parsed->entries);
		$this->assertSame(3, $parsed->malformed);
	}

	public function testSpamhausMalformedLinesAndMissingCidr(): void {
		$parsed = ListFormat::SpamhausJson->parser()->parse("{\"cidr\":\"192.0.2.0/24\"}\n{broken\n{\"sblid\":\"SBL1\"}\n{\"cidr\":\"300.0.0.0/8\"}\n");
		$this->assertSame(1, $parsed->entries);
		$this->assertSame(3, $parsed->malformed);
	}

	/**
	 * @return array<string, array{ListFormat, string}>
	 */
	public static function wrongFormat(): array {
		return [
			'Spamhaus, not JSON lines' => [ListFormat::SpamhausJson, "192.0.2.0/24\n198.51.100.0/24\n"],
			'AWS, not JSON' => [ListFormat::AwsJson, '<html></html>'],
			'AWS, another document' => [ListFormat::AwsJson, '{"regions": []}'],
			'Google, not JSON' => [ListFormat::GoogleJson, 'prefixes'],
			'Google, no prefixes' => [ListFormat::GoogleJson, '{"syncToken": "1"}'],
			'Oracle, no regions' => [ListFormat::OracleJson, '{"prefixes": []}'],
			'Oracle, a JSON string' => [ListFormat::OracleJson, '"regions"'],
		];
	}

	#[DataProvider('wrongFormat')]
	public function testAFileInAnotherFormatIsRefused(ListFormat $format, string $body): void {
		$this->expectException(ListFormatException::class);
		$format->parser()->parse($body);
	}

	public function testJsonEntriesOfTheWrongTypeAreMalformed(): void {
		$parsed = ListFormat::AwsJson->parser()->parse('{"prefixes": [{"ip_prefix": "192.0.2.0/24"}, {"ip_prefix": 42}, "x", {"region": "eu"}]}');
		$this->assertSame(1, $parsed->entries);
		$this->assertSame(3, $parsed->malformed);
	}

	/**
	 * @return array<string, array{ListFormat, string}>
	 */
	public static function overTheLimit(): array {
		$cidr = '';
		$spamhaus = '';
		$aws = [];
		for ($i = 0; $i < 4; $i++) {
			$cidr .= '192.0.2.' . $i . "/32\n";
			$spamhaus .= '{"cidr":"198.51.100.' . $i . "/32\"}\n";
			$aws[] = ['ip_prefix' => '203.0.113.' . $i . '/32'];
		}
		return [
			'plain text' => [ListFormat::Cidr, $cidr],
			'JSON lines' => [ListFormat::SpamhausJson, $spamhaus],
			'a JSON document' => [ListFormat::AwsJson, (string)json_encode(['prefixes' => $aws])],
		];
	}

	#[DataProvider('overTheLimit')]
	public function testParsingStopsAtTheFirstEntryOverTheLimit(ListFormat $format, string $body): void {
		$this->assertSame(4, $format->parser()->parse($body, 4)->entries, 'exactly the limit is fine');
		try {
			$format->parser()->parse($body, 3);
			$this->fail('a list just over the limit is refused');
		} catch (ListTooLongException $e) {
			$this->assertSame(3, $e->maxEntries);
		}
	}

	public function testNoRangeOverTheLimitIsKept(): void {
		$list = new ParsedList(2);
		$list->add('192.0.2.1');
		$list->add('not a range');
		$list->add('192.0.2.2');
		$this->assertSame(1, $list->malformed, 'malformed entries do not count against the limit');
		try {
			$list->add('192.0.2.3');
			$this->fail('the third range is refused');
		} catch (ListTooLongException) {
		}
		$this->assertCount(2, $list->ranges);
		$this->assertSame(2, $list->entries);
	}

	public function testAByteOrderMarkIsIgnored(): void {
		$parsed = ListFormat::Cidr->parser()->parse("\xef\xbb\xbf192.0.2.0/24\n");
		$this->assertSame(1, $parsed->entries);
		$this->assertSame(0, $parsed->malformed);
	}

	/**
	 * @return list<string>
	 */
	private static function ranges(ParsedList $parsed): array {
		return array_map(static fn (string $r): string => RangeCodec::format((int)$r[0], substr($r, 1, 32), substr($r, 33, 32)), $parsed->ranges);
	}

	private function fixture(string $name): string {
		return (string)file_get_contents(__DIR__ . '/../../fixtures/blocklists/' . $name);
	}
}
