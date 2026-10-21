<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Net;

use OCA\IntrusionDetection\Net\RangeCodec;
use OCA\IntrusionDetection\Net\SourceKey;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class RangeCodecTest extends TestCase {
	/**
	 * @return array<string, array{string, string, string}>
	 */
	public static function firstAndLast(): array {
		return [
			'IPv4 /24' => ['198.51.100.0/24', '198.51.100.0', '198.51.100.255'],
			'IPv4 /32' => ['198.51.100.7/32', '198.51.100.7', '198.51.100.7'],
			'IPv4 single address' => ['198.51.100.7', '198.51.100.7', '198.51.100.7'],
			'IPv4 /0' => ['0.0.0.0/0', '0.0.0.0', '255.255.255.255'],
			'IPv4 /31' => ['198.51.100.6/31', '198.51.100.6', '198.51.100.7'],
			'IPv4 odd prefix' => ['192.0.2.64/26', '192.0.2.64', '192.0.2.127'],
			'IPv4 host bits are ignored' => ['198.51.100.77/24', '198.51.100.0', '198.51.100.255'],
			'IPv6 /64' => ['2001:db8:1:2::/64', '2001:db8:1:2::', '2001:db8:1:2:ffff:ffff:ffff:ffff'],
			'IPv6 /128' => ['2001:db8::1/128', '2001:db8::1', '2001:db8::1'],
			'IPv6 single address' => ['2001:DB8::1', '2001:db8::1', '2001:db8::1'],
			'IPv6 /0' => ['::/0', '::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
			'IPv6 odd prefix' => ['2001:db8:a000::/37', '2001:db8:a000::', '2001:db8:a7ff:ffff:ffff:ffff:ffff:ffff'],
			'IPv4-mapped is IPv4' => ['::ffff:198.51.100.0/120', '198.51.100.0', '198.51.100.255'],
		];
	}

	#[DataProvider('firstAndLast')]
	public function testFirstAndLastAddress(string $cidr, string $first, string $last): void {
		$this->assertSame($first, RangeCodec::first($cidr));
		$this->assertSame($last, RangeCodec::last($cidr));
	}

	public function testIpv4IsStoredAsIpv4MappedHex(): void {
		$range = RangeCodec::parse('198.51.100.0/24');
		$this->assertSame(4, $range['family']);
		$this->assertSame('00000000000000000000ffffc6336400', $range['start']);
		$this->assertSame('00000000000000000000ffffc63364ff', $range['end']);
		$this->assertSame(RangeCodec::HEX_LENGTH, strlen($range['start']));
	}

	public function testIpv4MappedInputHasFamilyFour(): void {
		$this->assertSame(RangeCodec::parse('198.51.100.7'), RangeCodec::parse('::ffff:198.51.100.7'));
		$this->assertSame(4, RangeCodec::parse('::ffff:198.51.100.0/120')['family']);
		// Wider than the mapped block: an IPv6 range.
		$this->assertSame(6, RangeCodec::parse('::ffff:0:0/95')['family']);
	}

	public function testIpv6IsLowerCaseHex(): void {
		$range = RangeCodec::parse('2001:DB8:ABCD::/48');
		$this->assertSame(6, $range['family']);
		$this->assertSame('20010db8abcd00000000000000000000', $range['start']);
		$this->assertSame('20010db8abcdffffffffffffffffffff', $range['end']);
	}

	public function testStringOrderIsAddressOrder(): void {
		$addresses = ['0.0.0.1', '9.255.255.255', '10.0.0.0', '99.1.1.1', '100.0.0.0', '198.51.100.7', '255.255.255.255'];
		$hex = array_map(static fn (string $ip): string => RangeCodec::addressHex(SourceKey::fromIp($ip)), $addresses);
		$sorted = $hex;
		sort($sorted, SORT_STRING);
		$this->assertSame($hex, $sorted);
	}

	public function testAddressHexMatchesTheRangeOfASingleAddress(): void {
		$this->assertSame(RangeCodec::parse('198.51.100.7')['start'], RangeCodec::addressHex(SourceKey::fromIp('198.51.100.7')));
		$this->assertSame(RangeCodec::parse('2001:db8::7')['start'], RangeCodec::addressHex(SourceKey::fromIp('2001:db8::7')));
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function invalid(): array {
		return [
			'empty' => [''],
			'text' => ['not a range'],
			'IPv4 prefix too long' => ['198.51.100.0/33'],
			'IPv6 prefix too long' => ['2001:db8::/129'],
			'four-digit prefix' => ['198.51.100.0/0024'],
			'negative prefix' => ['198.51.100.0/-1'],
			'two prefixes' => ['198.51.100.0/24/8'],
			'octet out of range' => ['198.51.100.256/32'],
			'too few octets' => ['198.51.100/24'],
			'zone id' => ['fe80::1%eth0'],
			'host name' => ['example.com'],
			'html' => ['<html>'],
			'too long' => [str_repeat('1', 70)],
			'range with dash' => ['192.0.2.1-192.0.2.9'],
		];
	}

	#[DataProvider('invalid')]
	public function testInvalidInputIsRejected(string $input): void {
		$this->expectException(\InvalidArgumentException::class);
		RangeCodec::parse($input);
	}

	public function testFormatGivesACidrWhenItIsOne(): void {
		foreach (['198.51.100.0/24', '198.51.100.7/32', '0.0.0.0/0', '2001:db8:1:2::/64', '2001:db8::1/128', '::/0'] as $cidr) {
			$range = RangeCodec::parse($cidr);
			$this->assertSame($cidr, RangeCodec::format($range['family'], $range['start'], $range['end']));
		}
		$start = RangeCodec::parse('192.0.2.1')['start'];
		$end = RangeCodec::parse('192.0.2.9')['end'];
		$this->assertSame('192.0.2.1-192.0.2.9', RangeCodec::format(4, $start, $end));
	}

	public function testMergeJoinsOverlappingAndTouchingRangesOfOneFamily(): void {
		$merged = RangeCodec::merge([
			RangeCodec::parseCompact('198.51.100.128/25'),
			RangeCodec::parseCompact('198.51.100.0/25'),
			RangeCodec::parseCompact('198.51.100.7'),
			RangeCodec::parseCompact('203.0.113.0/24'),
			RangeCodec::parseCompact('2001:db8::/32'),
			RangeCodec::parseCompact('2001:db8:1::/48'),
		]);
		$this->assertSame(['198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32'], array_map(
			static fn (string $r): string => RangeCodec::format((int)$r[0], substr($r, 1, 32), substr($r, 33, 32)),
			$merged,
		));
	}

	public function testMergeNeverJoinsAcrossFamilies(): void {
		$merged = RangeCodec::merge([RangeCodec::parseCompact('255.255.255.255'), RangeCodec::parseCompact('::/0')]);
		$this->assertCount(2, $merged);
	}

	public function testSuccessor(): void {
		$this->assertSame(RangeCodec::parse('198.51.101.0')['start'], RangeCodec::successor(RangeCodec::parse('198.51.100.255')['start']));
		$this->assertNull(RangeCodec::successor(str_repeat('f', 32)));
	}

	public function testReservedTableMatchesItsKeys(): void {
		foreach (RangeCodec::RESERVED as $cidr => [$family, $start, $end]) {
			$this->assertSame(['family' => $family, 'start' => $start, 'end' => $end], RangeCodec::parse($cidr), $cidr);
		}
	}

	/**
	 * @return array<string, array{string, bool}>
	 */
	public static function reserved(): array {
		return [
			'private /8' => ['10.1.0.0/16', true],
			'contains a private block' => ['8.0.0.0/5', true],
			'CGNAT' => ['100.64.1.1', true],
			'loopback' => ['127.0.0.1', true],
			'IPv4 everything' => ['0.0.0.0/0', true],
			'unique local IPv6' => ['fd00::/8', true],
			'link-local IPv6' => ['fe80::1', true],
			'IPv6 loopback' => ['::1', true],
			'IPv6 everything' => ['::/0', true],
			'just below 10/8' => ['9.255.255.255', false],
			'just above 10/8' => ['11.0.0.0/8', false],
			'public IPv4' => ['198.51.100.0/24', false],
			'public IPv6' => ['2001:db8::/32', false],
		];
	}

	#[DataProvider('reserved')]
	public function testReservedSpaceIsRecognised(string $cidr, bool $reserved): void {
		$range = RangeCodec::parse($cidr);
		$this->assertSame($reserved, RangeCodec::overlapsReserved($range['family'], $range['start'], $range['end']));
	}
}
