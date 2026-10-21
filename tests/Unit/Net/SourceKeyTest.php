<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Net;

use OCA\IntrusionDetection\Net\SourceKey;
use Test\TestCase;

class SourceKeyTest extends TestCase {
	public function testIpv4KeysAreTheAddressAndItsSlash24(): void {
		$key = SourceKey::fromIp('198.51.100.7');
		$this->assertSame(4, $key->family);
		$this->assertSame('198.51.100.7', $key->ipKey);
		$this->assertSame('198.51.100.0/24', $key->netKey);
	}

	public function testIpv6KeysAreTheSlash64(): void {
		$key = SourceKey::fromIp('2001:DB8:1:2:abcd::7');
		$this->assertSame(6, $key->family);
		$this->assertSame('2001:db8:1:2:abcd::7', $key->ip);
		$this->assertSame('2001:db8:1:2::/64', $key->ipKey);
		$this->assertSame('2001:db8:1:2::/64', $key->netKey);
	}

	public function testTwoAddressesInOneSlash64ShareTheirKey(): void {
		$this->assertSame(SourceKey::fromIp('2001:db8:1:2::1')->ipKey, SourceKey::fromIp('2001:db8:1:2:ffff::9')->ipKey);
	}

	public function testIpv4MappedIpv6IsTreatedAsIpv4(): void {
		$key = SourceKey::fromIp('::ffff:198.51.100.7');
		$this->assertSame(4, $key->family);
		$this->assertSame('198.51.100.7', $key->ipKey);
	}

	public function testZoneIdIsIgnored(): void {
		$this->assertSame('fe80::1', SourceKey::fromIp('fe80::1%eth0')->ip);
	}

	public function testInvalidAddressIsRejected(): void {
		$this->assertNull(SourceKey::tryFromIp('example.org'));
		$this->assertNull(SourceKey::tryFromIp(''));
		$this->expectException(\InvalidArgumentException::class);
		SourceKey::fromIp('999.1.1.1');
	}

	public function testLoopback(): void {
		$this->assertTrue(SourceKey::fromIp('127.0.0.1')->isLoopback());
		$this->assertTrue(SourceKey::fromIp('127.8.9.10')->isLoopback());
		$this->assertTrue(SourceKey::fromIp('::1')->isLoopback());
		$this->assertFalse(SourceKey::fromIp('10.0.0.1')->isLoopback());
	}

	public function testSameNetworkNeedsTheSameFamily(): void {
		$a = SourceKey::fromIp('198.51.100.7');
		$this->assertTrue($a->sameNetwork(SourceKey::fromIp('198.51.100.200')));
		$this->assertFalse($a->sameNetwork(SourceKey::fromIp('198.51.101.7')));
		$this->assertFalse($a->sameNetwork(SourceKey::fromIp('2001:db8::1')));
	}

	public function testBinaryIsSixteenBytesAndSortsLikeTheAddress(): void {
		$low = SourceKey::fromIp('198.51.100.7')->binary();
		$high = SourceKey::fromIp('198.51.100.8')->binary();
		$this->assertSame(16, strlen($low));
		$this->assertLessThan(0, strcmp(bin2hex($low), bin2hex($high)));
	}

	public function testSourcesFromStoredIpKeys(): void {
		$this->assertSame('198.51.100.7', SourceKey::tryFromIpKey('198.51.100.7')?->ipKey);
		$v6 = SourceKey::tryFromIpKey('2001:db8:1:2::/64');
		$this->assertSame('2001:db8:1:2::/64', $v6?->ipKey);
		$this->assertSame(6, $v6?->family);
		$this->assertNull(SourceKey::tryFromIpKey('2001:db8:1:2::5'), 'An IPv6 key is always a /64');
		$this->assertNull(SourceKey::tryFromIpKey('198.51.100.0/24'), 'A network key is not an ip key');
		$this->assertNull(SourceKey::tryFromIpKey('2001:db8::/48'));
		$this->assertNull(SourceKey::tryFromIpKey('not an address'));
	}
}
