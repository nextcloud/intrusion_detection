<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

use OCP\Security\IRemoteHostValidator;

/**
 * Which addresses lists may be downloaded from: `https://` only, no
 * credentials in the address, and no host in the local network (core's
 * remote host rules, which an administrator can relax only in config.php with
 * `allow_local_remote_servers`).
 *
 * Applied when a list is saved, before every download, and to every redirect.
 */
class UrlPolicy {
	public const MAX_LENGTH = 2048;

	public function __construct(
		private readonly IRemoteHostValidator $hostValidator,
	) {
	}

	public function isAllowed(string $url): bool {
		if (!self::hasValidShape($url)) {
			return false;
		}
		$host = (string)parse_url($url, PHP_URL_HOST);
		return $this->hostValidator->isValid($host);
	}

	/**
	 * The checks that need no lookup: scheme, host, no user or password.
	 */
	public static function hasValidShape(string $url): bool {
		if ($url === '' || strlen($url) > self::MAX_LENGTH || preg_match('/[\x00-\x20\x7f]/', $url)) {
			return false;
		}
		$parts = parse_url($url);
		if ($parts === false || strtolower($parts['scheme'] ?? '') !== 'https' || ($parts['host'] ?? '') === '') {
			return false;
		}
		return !isset($parts['user']) && !isset($parts['pass']);
	}
}
