<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Net;

use OCA\IntrusionDetection\Db\KeyMatch;

/**
 * The IPv6 networks above a /64 that blocks escalate to: the /56 and the
 * /48 a /64 belongs to.
 *
 * The tables store IPv6 networks as /64 keys in the text form of
 * {@see SourceKey} (`2001:db8:1:2a00::/64`). That form always compresses the
 * trailing zero groups, so the /64 keys inside a /56 or /48 can be found
 * with a few LIKE patterns that share their start, which {@see KeyMatch}
 * turns into a key range the indexes on the key columns serve.
 */
final class Ipv6Networks {
	public const PREFIXES = [56, 48];

	/**
	 * The network of a given prefix length that contains the source, as
	 * `2001:db8:1:2a00::/56`.
	 */
	public static function key(SourceKey $source, int $prefix): string {
		$packed = (string)inet_pton($source->ip);
		$bytes = intdiv($prefix, 8);
		return (string)inet_ntop(substr($packed, 0, $bytes) . str_repeat("\0", 16 - $bytes)) . '/' . $prefix;
	}

	/**
	 * The /64 keys inside a /56 or /48 network key.
	 *
	 * @throws \InvalidArgumentException for anything else
	 */
	public static function slash64Keys(string $networkKey): KeyMatch {
		[$address, $length] = array_pad(explode('/', $networkKey, 2), 2, '');
		$packed = @inet_pton($address);
		if ($packed === false || strlen($packed) !== 16 || !in_array($length, ['48', '56'], true)) {
			throw new \InvalidArgumentException('Not an IPv6 /48 or /56');
		}
		$groups = array_values((array)unpack('n8', $packed));
		$head = dechex((int)$groups[0]) . ':' . dechex((int)$groups[1]) . ':' . dechex((int)$groups[2]) . ':';
		// The /64 whose fourth group is 0 compresses differently; it is matched exactly.
		$zero = (string)inet_ntop(substr($packed, 0, 6) . str_repeat("\0", 10)) . '/64';
		if ($length === '48') {
			return new KeyMatch([$zero], [$head . '%::/64']);
		}
		$high = ord($packed[6]);
		if ($high === 0) {
			// Fourth group 1 to ff: one or two hex digits.
			return new KeyMatch([$zero], [$head . '_::/64', $head . '__::/64']);
		}
		// Fourth group from high * 256 to high * 256 + 255: the high byte and two more digits.
		return new KeyMatch([], [$head . dechex($high) . '__::/64']);
	}
}
