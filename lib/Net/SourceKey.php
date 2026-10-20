<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Net;

/**
 * The normalised forms of one client address.
 *
 * - `ipKey`: the address itself for IPv4; the /64 for IPv6, because one IPv6
 *   client usually controls a whole /64.
 * - `netKey`: the /24 for IPv4; the /64 for IPv6.
 *
 * IPv4-mapped IPv6 addresses (`::ffff:198.51.100.7`) are treated as IPv4.
 */
final class SourceKey {
	private function __construct(
		public readonly string $ip,
		public readonly int $family,
		public readonly string $ipKey,
		public readonly string $netKey,
	) {
	}

	/**
	 * @throws \InvalidArgumentException for anything that is not an IP address
	 */
	public static function fromIp(string $ip): self {
		$ip = trim($ip);
		// Zone ids (fe80::1%eth0) are not part of the address.
		$percent = strpos($ip, '%');
		if ($percent !== false) {
			$ip = substr($ip, 0, $percent);
		}
		$packed = @inet_pton($ip);
		if ($packed === false) {
			throw new \InvalidArgumentException('Not an IP address');
		}
		if (strlen($packed) === 16 && str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff")) {
			$packed = substr($packed, 12);
		}
		if (strlen($packed) === 4) {
			$canonical = (string)inet_ntop($packed);
			$net = (string)inet_ntop(substr($packed, 0, 3) . "\0") . '/24';
			return new self($canonical, 4, $canonical, $net);
		}
		$canonical = (string)inet_ntop($packed);
		$prefix = (string)inet_ntop(substr($packed, 0, 8) . str_repeat("\0", 8)) . '/64';
		return new self($canonical, 6, $prefix, $prefix);
	}

	public static function tryFromIp(string $ip): ?self {
		try {
			return self::fromIp($ip);
		} catch (\InvalidArgumentException) {
			return null;
		}
	}

	/**
	 * Whether two addresses are in the same network: the same /24 for IPv4,
	 * the same /64 for IPv6. Addresses of different families never are.
	 */
	public function sameNetwork(self $other): bool {
		return $this->family === $other->family && $this->netKey === $other->netKey;
	}

	public function isLoopback(): bool {
		return ($this->family === 4 && str_starts_with($this->ip, '127.')) || $this->ip === '::1';
	}

	/**
	 * The address as 16 bytes (IPv4 as IPv4-mapped IPv6), for range comparisons.
	 */
	public function binary(): string {
		$packed = (string)inet_pton($this->ip);
		return strlen($packed) === 4 ? str_repeat("\0", 10) . "\xff\xff" . $packed : $packed;
	}
}
