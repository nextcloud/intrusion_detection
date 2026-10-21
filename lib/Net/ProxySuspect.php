<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Net;

use OCA\IntrusionDetection\Db\LoginMapper;
use OCP\IConfig;

/**
 * Whether Nextcloud seems to see a reverse proxy instead of its visitors:
 * no trusted proxy is configured, and several of the latest successful
 * logins by different people came from one private address.
 *
 * Read by the reverse proxy setup check, and by the ban service before it
 * blocks a private address: blocking the proxy would lock everyone out.
 */
class ProxySuspect {
	/** How many of the latest logins are looked at */
	public const SAMPLE = 50;
	/** Different accounts from one private address that make it look like a proxy */
	public const MIN_USERS = 3;

	public function __construct(
		private readonly LoginMapper $logins,
		private readonly IConfig $config,
	) {
	}

	/**
	 * The private address most of the latest logins of different people
	 * came from, and how many accounts, while no trusted proxy is configured.
	 *
	 * @return array{0: SourceKey, 1: int}|null
	 */
	public function suspect(): ?array {
		$accounts = $this->accountsPerPrivateAddress();
		$suspect = null;
		foreach ($accounts as $ipKey => $count) {
			$source = SourceKey::tryFromIpKey($ipKey);
			if ($source !== null && $count >= self::MIN_USERS && ($suspect === null || $count > $suspect[1])) {
				$suspect = [$source, $count];
			}
		}
		return $suspect;
	}

	/**
	 * How many different people logged in from the address among the latest
	 * logins, when it looks like an unconfigured reverse proxy; 0 otherwise.
	 * Costs nothing for public addresses or with trusted proxies configured.
	 */
	public function accountsBehind(SourceKey $source): int {
		if (!self::isPrivate($source)) {
			return 0;
		}
		$count = $this->accountsPerPrivateAddress()[$source->ipKey] ?? 0;
		return $count >= self::MIN_USERS ? $count : 0;
	}

	/**
	 * Whether no trusted proxy is configured.
	 */
	public function unconfigured(): bool {
		$proxies = $this->config->getSystemValue('trusted_proxies', []);
		return !is_array($proxies) || $proxies === [];
	}

	public static function isPrivate(SourceKey $source): bool {
		return $source->isLoopback()
			|| filter_var($source->ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
	}

	/**
	 * @return array<string, int> accounts per private ip key, empty with trusted proxies configured
	 */
	private function accountsPerPrivateAddress(): array {
		if (!$this->unconfigured()) {
			return [];
		}
		/** @var array<string, array<string, true>> $users */
		$users = [];
		foreach ($this->logins->recent(self::SAMPLE) as $row) {
			$source = SourceKey::tryFromIpKey($row['ipKey']);
			if ($source !== null && self::isPrivate($source)) {
				$users[$row['ipKey']][$row['uid']] = true;
			}
		}
		return array_map('count', $users);
	}
}
