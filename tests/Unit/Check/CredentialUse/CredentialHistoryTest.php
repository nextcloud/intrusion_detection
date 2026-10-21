<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check\CredentialUse;

use OCA\IntrusionDetection\Check\CredentialUse\CredentialHistory;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialSwitch;
use OCA\IntrusionDetection\Net\SourceKey;
use Test\TestCase;

/**
 * The switching rules of concept section 10.12, on one credential's
 * history as it goes through the cache between requests.
 */
class CredentialHistoryTest extends TestCase {
	private const HOME = '198.51.100.7';
	private const HOME_OTHER_HOST = '198.51.100.99';
	private const MOBILE = '203.0.113.50';
	private const THIRD = '192.0.2.10';
	private const HOME_V6 = '2001:db8:1:2::7';
	private const MOBILE_V6 = '2001:db8:9:9::1';

	private array $cached = [];
	private int $now = 1792411200;
	private int $window = 900;
	private int $minSwitches = 3;
	private int $thresholdReads = 0;

	public function testOneMoveFromWiFiToMobileDataNeverFires(): void {
		$this->assertNull($this->use(self::HOME));
		$this->now += 60;
		$this->assertNull($this->use(self::MOBILE), 'One switch');
		for ($i = 0; $i < 50; $i++) {
			$this->now += 30;
			$this->assertNull($this->use(self::MOBILE), 'It stays on mobile data');
		}
	}

	public function testRealBackAndForthBetweenTwoNetworksFires(): void {
		$this->assertNull($this->use(self::HOME));
		$this->now += 20;
		$this->assertNull($this->use(self::MOBILE), 'A to B: one switch');
		$this->now += 20;
		$this->assertNull($this->use(self::HOME), 'B to A: two switches');
		$this->now += 20;
		$switch = $this->use(self::MOBILE);
		$this->assertInstanceOf(CredentialSwitch::class, $switch, 'A to B again: three switches');
		$this->assertSame(self::HOME, $switch->otherIp);
		$this->assertSame('198.51.100.0/24', $switch->otherNet);
		$this->assertSame(self::MOBILE, $switch->currentIp);
		$this->assertSame('203.0.113.0/24', $switch->currentNet);
		$this->assertSame(4, $switch->family);
		$this->assertSame(3, $switch->switches);
		$this->assertSame($this->now - 40, $switch->firstSwitchAt);
		$this->assertSame($this->now, $switch->at);
	}

	public function testTheThresholdsAreOnlyReadOnASwitch(): void {
		$this->use(self::HOME);
		$this->now += CredentialHistory::REFRESH;
		$this->use(self::HOME);
		$this->assertSame(0, $this->thresholdReads, 'First use and refresh need no settings');
		$this->use(self::MOBILE);
		$this->assertSame(1, $this->thresholdReads);
	}

	public function testItFiresAtMostOncePerWindow(): void {
		$this->pingPong(4);
		$fired = 0;
		for ($i = 0; $i < 10; $i++) {
			$this->now += 10;
			$fired += $this->use($i % 2 === 0 ? self::HOME : self::MOBILE) !== null ? 1 : 0;
		}
		$this->assertSame(0, $fired, 'Not again within the window');
		$this->now += $this->window;
		$this->use(self::HOME);
		$this->now += 10;
		$this->use(self::MOBILE);
		$this->now += 10;
		$this->assertNotNull($this->use(self::HOME), 'Again once the window has passed');
	}

	public function testSwitchesOutsideTheWindowDoNotCount(): void {
		$this->assertNull($this->use(self::HOME));
		$this->now += 10;
		$this->assertNull($this->use(self::MOBILE));
		$this->now += 600;
		$this->assertNull($this->use(self::HOME));
		$this->now += 600;
		$this->assertNull($this->use(self::MOBILE), 'Only two of the three switches are within 15 minutes');
		$this->now += 600;
		$this->assertNull($this->use(self::HOME));
	}

	public function testAThirdNetworkStartsOver(): void {
		$this->use(self::HOME);
		$this->now += 10;
		$this->use(self::MOBILE);
		$this->now += 10;
		$this->use(self::HOME);
		$this->now += 10;
		$this->assertNull($this->use(self::THIRD), 'A, B, A, C is travelling, not two places at once');
		$this->now += 10;
		$this->assertNull($this->use(self::HOME), 'A and C: two switches so far');
		$this->now += 10;
		$this->assertNotNull($this->use(self::THIRD), 'A, C, A, C');
	}

	public function testAlternatingBetweenIpv4AndIpv6IsIgnoredAndWritesNothing(): void {
		$this->assertNull($this->use(self::HOME));
		$this->assertNull($this->use(self::HOME_V6));
		for ($i = 0; $i < 20; $i++) {
			$this->now += 5;
			$history = CredentialHistory::fromCache($this->cached);
			$address = SourceKey::fromIp($i % 2 === 0 ? self::HOME : self::HOME_V6);
			$this->assertTrue($history->isCurrent($address, $this->now), 'A dual-stack device is the common case on both families');
		}
	}

	public function testIpv6NetworksSwitchLikeIpv4Ones(): void {
		$this->use(self::HOME_V6);
		$this->use(self::HOME);
		$this->now += 10;
		$this->use(self::MOBILE_V6);
		$this->use(self::HOME);
		$this->now += 10;
		$this->use(self::HOME_V6);
		$this->now += 10;
		$switch = $this->use(self::MOBILE_V6);
		$this->assertNotNull($switch, 'The IPv4 uses in between do not interrupt the IPv6 stream');
		$this->assertSame(6, $switch->family);
		$this->assertSame('2001:db8:1:2::/64', $switch->otherNet);
	}

	public function testAddressesInOneNetworkAreOneVisit(): void {
		$this->use(self::HOME);
		for ($i = 0; $i < 10; $i++) {
			$this->now += 10;
			$this->assertTrue(CredentialHistory::fromCache($this->cached)->isCurrent(SourceKey::fromIp($i % 2 === 0 ? self::HOME_OTHER_HOST : self::HOME), $this->now));
		}
	}

	public function testTheNewestVisitIsRefreshedEveryFiveMinutes(): void {
		$this->use(self::HOME);
		$this->now += CredentialHistory::REFRESH - 1;
		$this->assertTrue(CredentialHistory::fromCache($this->cached)->isCurrent(SourceKey::fromIp(self::HOME), $this->now));
		$this->now += 1;
		$this->assertFalse(CredentialHistory::fromCache($this->cached)->isCurrent(SourceKey::fromIp(self::HOME), $this->now));
		$this->use(self::HOME_OTHER_HOST);
		$visit = $this->cached['v'][0];
		$this->assertSame($this->now, $visit[3], 'Last use refreshed');
		$this->assertSame(self::HOME_OTHER_HOST, $visit[4], 'With the latest address');
		$this->assertCount(1, $this->cached['v']);
	}

	public function testTwoAccountsThatShareAPasswordAreNotOneCredential(): void {
		$alice = hash('crc32b', 'alice');
		$bob = hash('crc32b', 'bob');
		for ($i = 0; $i < 8; $i++) {
			$this->now += 10;
			$this->assertNull($this->use($i % 2 === 0 ? self::HOME : self::MOBILE, $i % 2 === 0 ? $alice : $bob));
		}
	}

	public function testATokenWithoutAccountNameMatchesTheBasicUses(): void {
		$alice = hash('crc32b', 'alice');
		$this->use(self::HOME, $alice);
		$this->now += 10;
		$this->use(self::MOBILE, '');
		$this->now += 10;
		$this->use(self::HOME, $alice);
		$this->now += 10;
		$this->assertNotNull($this->use(self::MOBILE, ''), 'The same app password over Basic and as a Bearer token');
	}

	public function testTheMinimumNumberOfSwitchesIsHonoured(): void {
		$this->minSwitches = 2;
		$this->use(self::HOME);
		$this->now += 10;
		$this->assertNull($this->use(self::MOBILE));
		$this->now += 10;
		$this->assertNotNull($this->use(self::HOME), 'A, B, A with min_switches 2');

		$this->cached = [];
		$this->minSwitches = 20;
		$this->now += 3600;
		$fired = $this->pingPong(20);
		$this->assertSame(1, $fired, 'Fires at the twentieth switch');
	}

	public function testOnlyFewVisitsAreKeptButTheNewestOfEachFamilyStays(): void {
		$this->use(self::HOME_V6);
		foreach ([self::HOME, self::MOBILE, self::THIRD, self::HOME, self::MOBILE, self::THIRD] as $address) {
			$this->now += 10;
			$this->use($address);
		}
		$this->assertCount(CredentialHistory::MAX_VISITS, $this->cached['v']);
		$this->assertSame(6, $this->cached['v'][0][1], 'The only IPv6 visit is kept');
		$this->assertTrue(CredentialHistory::fromCache($this->cached)->isCurrent(SourceKey::fromIp(self::HOME_V6), $this->now));
	}

	public function testMalformedCacheValuesCountAsNoHistory(): void {
		foreach ([null, false, 'text', 42, ['v' => 'x'], ['v' => [['a', 'b']]], ['r' => [4 => 'x'], 'f' => 'soon']] as $value) {
			$history = CredentialHistory::fromCache($value);
			$this->assertFalse($history->isCurrent(SourceKey::fromIp(self::HOME), $this->now));
			$this->assertNull($history->record(SourceKey::fromIp(self::HOME), '', $this->now, fn (): array => [900, 3]));
		}
	}

	/**
	 * @return int how often it fired
	 */
	private function pingPong(int $switches): int {
		$fired = $this->use(self::HOME) !== null ? 1 : 0;
		for ($i = 1; $i <= $switches; $i++) {
			$this->now += 10;
			$fired += $this->use($i % 2 === 1 ? self::MOBILE : self::HOME) !== null ? 1 : 0;
		}
		return $fired;
	}

	/**
	 * One request with the credential, as the tracker handles it.
	 */
	private function use(string $ip, string $tag = ''): ?CredentialSwitch {
		$history = CredentialHistory::fromCache($this->cached);
		$source = SourceKey::fromIp($ip);
		if ($history->isCurrent($source, $this->now)) {
			return null;
		}
		$switch = $history->record($source, $tag, $this->now, function (): array {
			$this->thresholdReads++;
			return [$this->window, $this->minSwitches];
		});
		// Through serialisation, as a distributed cache stores it.
		$this->cached = unserialize(serialize($history->toCache()));
		return $switch;
	}
}
