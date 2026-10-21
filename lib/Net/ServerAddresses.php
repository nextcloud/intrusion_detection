<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Net;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCP\IAppConfig;

/**
 * This server's own addresses, which are never blocked: the one the current
 * web request came in on (`SERVER_ADDR`), and those seen in earlier web
 * requests, for cron and occ, where there is no web request. Each web
 * server adds its own when it first resolves a verdict with it
 * ({@see observe()}): a write only when an address is new, at most
 * MAX_REMEMBERED kept, the latest first.
 */
class ServerAddresses {
	public const MAX_REMEMBERED = 16;

	public function __construct(
		private readonly IAppConfig $appConfig,
	) {
	}

	/**
	 * Remember the address of this web request's server, if it is new.
	 * Costs one read of the app config, which is in memory.
	 */
	public function observe(): void {
		$own = $this->current();
		if ($own === null) {
			return;
		}
		$known = $this->remembered();
		if (in_array($own->ip, $known, true)) {
			return;
		}
		array_unshift($known, $own->ip);
		$this->appConfig->setValueArray(Application::APP_ID, GlobalSettings::SERVER_ADDRESSES, array_slice($known, 0, self::MAX_REMEMBERED));
	}

	public function contains(SourceKey $source): bool {
		foreach ($this->all() as $own) {
			if ($own->ip === $source->ip) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return list<SourceKey> the current one first, then the remembered ones
	 */
	public function all(): array {
		$all = [];
		$current = $this->current();
		if ($current !== null) {
			$all[$current->ip] = $current;
		}
		foreach ($this->remembered() as $ip) {
			$source = SourceKey::tryFromIp($ip);
			if ($source !== null) {
				$all[$source->ip] ??= $source;
			}
		}
		return array_values($all);
	}

	private function current(): ?SourceKey {
		$address = $_SERVER['SERVER_ADDR'] ?? null;
		return is_string($address) ? SourceKey::tryFromIp($address) : null;
	}

	/**
	 * @return list<string>
	 */
	private function remembered(): array {
		$stored = $this->appConfig->getValueArray(Application::APP_ID, GlobalSettings::SERVER_ADDRESSES, []);
		return array_values(array_filter($stored, 'is_string'));
	}
}
