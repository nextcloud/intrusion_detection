<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Net;

use OCA\IntrusionDetection\AdminChange\WatchedSettings;
use OCP\IAppConfig;

/**
 * The address ranges no block may cover: loopback, the server's own
 * addresses ({@see ServerAddresses}) and the brute-force allowlist.
 *
 * {@see RemoteAddressResolver} answers this for one address; this class
 * answers it for networks, before a network is blocked and when blocks are
 * written for a firewall. The allowlist is read from where core keeps it
 * (app `bruteForce`, keys `whitelist_*`, one range each), because core has
 * no API that lists it.
 */
class ProtectedRanges {
	private const LOOPBACK = ['127.0.0.0/8', '::1/128'];

	/** @var list<array{0: int, 1: string, 2: string}>|null */
	private ?array $ranges = null;

	public function __construct(
		private readonly IAppConfig $appConfig,
		private readonly ServerAddresses $servers,
	) {
	}

	/**
	 * Every protected range as family, first and last address (hex, see
	 * {@see RangeCodec}), sorted and merged.
	 *
	 * @return list<array{0: int, 1: string, 2: string}>
	 */
	public function ranges(): array {
		if ($this->ranges !== null) {
			return $this->ranges;
		}
		$inputs = self::LOOPBACK;
		foreach ($this->servers->all() as $own) {
			$inputs[] = $own->ip;
		}
		foreach ($this->appConfig->getKeys(WatchedSettings::BRUTEFORCE_APP) as $key) {
			if (str_starts_with($key, WatchedSettings::BRUTEFORCE_PREFIX)) {
				$inputs[] = $this->appConfig->getValueString(WatchedSettings::BRUTEFORCE_APP, $key);
			}
		}
		$compact = [];
		foreach ($inputs as $input) {
			try {
				$compact[] = RangeCodec::parseCompact($input);
			} catch (\InvalidArgumentException) {
				// Core skips entries it cannot parse, too.
			}
		}
		$this->ranges = array_map(
			static fn (string $range): array => [(int)$range[0], substr($range, 1, 32), substr($range, 33, 32)],
			RangeCodec::merge($compact),
		);
		return $this->ranges;
	}

	/**
	 * Whether a range (family, first and last address in hex) touches a protected range.
	 */
	public function overlaps(int $family, string $start, string $end): bool {
		foreach ($this->ranges() as [$rangeFamily, $rangeStart, $rangeEnd]) {
			if ($rangeFamily === $family && strcmp($start, $rangeEnd) <= 0 && strcmp($end, $rangeStart) >= 0) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether a CIDR (as stored in a block) touches a protected range.
	 */
	public function overlapsCidr(string $cidr): bool {
		try {
			$range = RangeCodec::parse($cidr);
		} catch (\InvalidArgumentException) {
			return false;
		}
		return $this->overlaps($range['family'], $range['start'], $range['end']);
	}
}
