<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Net\Ipv6Networks;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * The LIKE patterns for the /64 keys of a /56 or /48 find exactly the /64s
 * inside it, on the database, whatever zeros the address has.
 */
#[Group('DB')]
class Ipv6NetworksTest extends IntegrationTestCase {
	/**
	 * @return array<string, array{string}>
	 */
	public static function networks(): array {
		return [
			'ordinary' => ['2001:db8:1:2a00::'],
			'zero third group' => ['2001:db8:0:1200::'],
			'zero fourth group' => ['2001:db8:5::'],
			'zero high byte' => ['2001:db8:5:ff::'],
			'zeros everywhere' => ['2001::'],
		];
	}

	#[DataProvider('networks')]
	public function testTheKeysOfANetworkAreFoundExactly(string $network): void {
		foreach ([56, 48] as $prefix) {
			$this->clear();
			$base = (string)inet_pton($network);
			$bytes = intdiv($prefix, 8);
			$inside = [];
			$logins = Server::get(LoginMapper::class);
			for ($i = 0; $i < 60; $i++) {
				$packed = substr($base, 0, $bytes) . random_bytes(8 - $bytes) . str_repeat("\0", 8);
				if ($i % 3 === 0) {
					// Many zero groups, which the text form compresses.
					$packed[6] = $prefix === 48 ? "\0" : $packed[6];
					$packed[7] = "\0";
				}
				$outside = $packed;
				$flip = random_int(0, $bytes - 1);
				$outside[$flip] = chr(ord($outside[$flip]) ^ (1 << random_int(0, 7)));
				$in = SourceKey::fromIp((string)inet_ntop($packed));
				$out = SourceKey::fromIp((string)inet_ntop($outside));
				$logins->record($in->ipKey, $in->netKey, 'in' . $i, 1);
				$logins->record($out->ipKey, $out->netKey, 'out' . $i, 1);
				$inside['in' . $i] = true;
			}
			$key = Ipv6Networks::key(SourceKey::fromIp($network . '1'), $prefix);
			$this->assertSame(count($inside), $logins->distinctUsersForNets(Ipv6Networks::slash64Keys($key), 0), $key);
		}
	}

	public function testNetworkKeys(): void {
		$source = SourceKey::fromIp('2001:db8:1:2a77:1:2:3:4');
		$this->assertSame('2001:db8:1:2a00::/56', Ipv6Networks::key($source, 56));
		$this->assertSame('2001:db8:1::/48', Ipv6Networks::key($source, 48));
		$this->expectException(\InvalidArgumentException::class);
		Ipv6Networks::slash64Keys('2001:db8:1:2::/64');
	}

	private function clear(): void {
		$this->db->getQueryBuilder()->delete(LoginMapper::TABLE)->executeStatement();
	}
}
