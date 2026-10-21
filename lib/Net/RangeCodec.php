<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Net;

/**
 * Converts between CIDR ranges and the form the blocklist tables store.
 *
 * Every address is 16 bytes (IPv4 as IPv4-mapped IPv6, `::ffff:a.b.c.d`),
 * written as 32 lower-case hex characters. Because the strings have a fixed
 * length and use only `0-9a-f`, comparing them as strings orders them like
 * the addresses, on every database.
 *
 * A range in compact form is one string: the family (`4` or `6`), then the
 * first and the last address, 65 characters in all. Sorting compact ranges
 * as strings sorts them by family and first address.
 */
final class RangeCodec {
	public const HEX_LENGTH = 32;
	public const COMPACT_LENGTH = 65;
	private const MAPPED_PREFIX = "\0\0\0\0\0\0\0\0\0\0\xff\xff";
	private const MAX_INPUT_LENGTH = 64;

	/**
	 * Networks that are never put on a list: private, loopback, link-local,
	 * shared (CGNAT) and unspecified addresses. Lists that contain them (such
	 * as the bogon part of FireHOL level 1) would otherwise block the office
	 * network or the reverse proxy. Each as family, first and last address;
	 * a test checks the values against the CIDR in the key.
	 */
	public const RESERVED = [
		'0.0.0.0/8' => [4, '00000000000000000000ffff00000000', '00000000000000000000ffff00ffffff'],
		'10.0.0.0/8' => [4, '00000000000000000000ffff0a000000', '00000000000000000000ffff0affffff'],
		'100.64.0.0/10' => [4, '00000000000000000000ffff64400000', '00000000000000000000ffff647fffff'],
		'127.0.0.0/8' => [4, '00000000000000000000ffff7f000000', '00000000000000000000ffff7fffffff'],
		'169.254.0.0/16' => [4, '00000000000000000000ffffa9fe0000', '00000000000000000000ffffa9feffff'],
		'172.16.0.0/12' => [4, '00000000000000000000ffffac100000', '00000000000000000000ffffac1fffff'],
		'192.168.0.0/16' => [4, '00000000000000000000ffffc0a80000', '00000000000000000000ffffc0a8ffff'],
		'::/128' => [6, '00000000000000000000000000000000', '00000000000000000000000000000000'],
		'::1/128' => [6, '00000000000000000000000000000001', '00000000000000000000000000000001'],
		'fc00::/7' => [6, 'fc000000000000000000000000000000', 'fdffffffffffffffffffffffffffffff'],
		'fe80::/10' => [6, 'fe800000000000000000000000000000', 'febfffffffffffffffffffffffffffff'],
	];

	/**
	 * Parse a CIDR range, or a single address as the smallest range that
	 * contains it. Host bits below the prefix are ignored, as firewalls do.
	 *
	 * @return array{family: int, start: string, end: string} start and end as hex
	 * @throws \InvalidArgumentException for anything that is not an IPv4 or IPv6 range
	 */
	public static function parse(string $input): array {
		$input = trim($input);
		if ($input === '' || strlen($input) > self::MAX_INPUT_LENGTH || !preg_match('#^[0-9a-fA-F:.]+(/[0-9]{1,3})?$#', $input)) {
			throw new \InvalidArgumentException('Not a range');
		}
		$parts = explode('/', $input, 2);
		$address = $parts[0];
		if (filter_var($address, FILTER_VALIDATE_IP) === false) {
			throw new \InvalidArgumentException('Not an address');
		}
		$packed = inet_pton($address);
		if ($packed === false) {
			throw new \InvalidArgumentException('Not an address');
		}
		$isV4 = strlen($packed) === 4;
		$maxPrefix = $isV4 ? 32 : 128;
		$prefix = isset($parts[1]) ? (int)$parts[1] : $maxPrefix;
		if ($prefix > $maxPrefix) {
			throw new \InvalidArgumentException('Prefix too long');
		}
		if ($isV4) {
			$packed = self::MAPPED_PREFIX . $packed;
			$prefix += 96;
		}
		$family = $isV4 || ($prefix >= 96 && str_starts_with($packed, self::MAPPED_PREFIX)) ? 4 : 6;

		$mask = self::mask($prefix);
		return [
			'family' => $family,
			'start' => bin2hex($packed & $mask),
			'end' => bin2hex($packed | ~$mask),
		];
	}

	/**
	 * The range in compact form (family, first, last).
	 *
	 * @throws \InvalidArgumentException
	 */
	public static function parseCompact(string $input): string {
		$range = self::parse($input);
		return $range['family'] . $range['start'] . $range['end'];
	}

	/**
	 * One address as 32 hex characters, IPv4 as IPv4-mapped.
	 */
	public static function addressHex(SourceKey $source): string {
		return bin2hex($source->binary());
	}

	/**
	 * The first of the ranges (CIDR or single addresses) that contains the
	 * address, or null. Entries that are not ranges are skipped.
	 *
	 * @param list<string> $ranges
	 */
	public static function firstContaining(array $ranges, SourceKey $source): ?string {
		$hex = self::addressHex($source);
		foreach ($ranges as $range) {
			try {
				$parsed = self::parse($range);
			} catch (\InvalidArgumentException) {
				continue;
			}
			if (strcmp($parsed['start'], $hex) <= 0 && strcmp($hex, $parsed['end']) <= 0) {
				return $range;
			}
		}
		return null;
	}

	/**
	 * The first address of a range, as text.
	 *
	 * @throws \InvalidArgumentException
	 */
	public static function first(string $cidr): string {
		$range = self::parse($cidr);
		return self::hexToAddress($range['start'], $range['family']);
	}

	/**
	 * The last address of a range, as text.
	 *
	 * @throws \InvalidArgumentException
	 */
	public static function last(string $cidr): string {
		$range = self::parse($cidr);
		return self::hexToAddress($range['end'], $range['family']);
	}

	/**
	 * A stored address back as text: `198.51.100.7` or `2001:db8::1`.
	 */
	public static function hexToAddress(string $hex, int $family): string {
		$packed = (string)hex2bin($hex);
		if ($family === 4) {
			$packed = substr($packed, 12);
		}
		return (string)inet_ntop($packed);
	}

	/**
	 * A stored range as text: a CIDR when it is one, otherwise "first-last".
	 */
	public static function format(int $family, string $start, string $end): string {
		$first = (string)hex2bin($start);
		$last = (string)hex2bin($end);
		for ($prefix = $family === 4 ? 96 : 0; $prefix <= 128; $prefix++) {
			$mask = self::mask($prefix);
			if (($first & $mask) === $first && ($first | ~$mask) === $last) {
				return self::hexToAddress($start, $family) . '/' . ($family === 4 ? $prefix - 96 : $prefix);
			}
		}
		return self::hexToAddress($start, $family) . '-' . self::hexToAddress($end, $family);
	}

	/**
	 * Whether a range touches private, loopback, link-local, shared or
	 * unspecified address space.
	 */
	public static function overlapsReserved(int $family, string $start, string $end): bool {
		foreach (self::RESERVED as [$reservedFamily, $reservedStart, $reservedEnd]) {
			if ($reservedFamily === $family && strcmp($start, $reservedEnd) <= 0 && strcmp($end, $reservedStart) >= 0) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Sort compact ranges and merge those that overlap or touch, so that the
	 * ranges of one list never overlap. A lookup then only has to look at the
	 * nearest range that starts at or below an address.
	 *
	 * @param list<string> $ranges compact ranges
	 * @return list<string>
	 */
	public static function merge(array $ranges): array {
		sort($ranges, SORT_STRING);
		$merged = [];
		$current = null;
		foreach ($ranges as $range) {
			if ($current === null) {
				$current = $range;
				continue;
			}
			$currentEnd = substr($current, 33, 32);
			$next = self::successor($currentEnd);
			if ($current[0] === $range[0] && ($next === null || strcmp(substr($range, 1, 32), $next) <= 0)) {
				$end = substr($range, 33, 32);
				if (strcmp($end, $currentEnd) > 0) {
					$current = substr($current, 0, 33) . $end;
				}
				continue;
			}
			$merged[] = $current;
			$current = $range;
		}
		if ($current !== null) {
			$merged[] = $current;
		}
		return $merged;
	}

	/**
	 * The address after the given one, or null after the very last address.
	 */
	public static function successor(string $hex): ?string {
		$bytes = (string)hex2bin($hex);
		for ($i = 15; $i >= 0; $i--) {
			$byte = ord($bytes[$i]);
			if ($byte < 255) {
				$bytes[$i] = chr($byte + 1);
				return bin2hex($bytes);
			}
			$bytes[$i] = "\0";
		}
		return null;
	}

	/**
	 * 16-byte network mask for a prefix length of 0 to 128.
	 */
	private static function mask(int $prefix): string {
		$mask = str_repeat("\xff", intdiv($prefix, 8));
		if ($prefix % 8 !== 0) {
			$mask .= chr((0xff << (8 - $prefix % 8)) & 0xff);
		}
		return str_pad($mask, 16, "\0");
	}
}
