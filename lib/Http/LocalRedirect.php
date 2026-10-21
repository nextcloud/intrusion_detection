<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Http;

use OCP\IURLGenerator;

/**
 * Where the app's own pages (verify, password) continue to: the page the
 * user wanted, if it is a path on this server, else the start page. Never
 * another host, so a crafted link cannot send anyone away.
 */
class LocalRedirect {
	public const MAX_LENGTH = 2000;

	public function __construct(
		private readonly IURLGenerator $urlGenerator,
	) {
	}

	/**
	 * The absolute URL to continue to.
	 *
	 * @param list<string> $excluded paths that are never continued to, such as the page itself
	 */
	public function target(string $url, array $excluded = []): string {
		return self::isSafe($url, $excluded)
			? $this->urlGenerator->getAbsoluteURL($url)
			: $this->urlGenerator->linkToDefaultPageUrl();
	}

	/**
	 * A local path: one leading slash, no scheme or host, no backslashes or
	 * control characters, and none of the excluded paths.
	 *
	 * @param list<string> $excluded
	 */
	public static function isSafe(string $url, array $excluded = []): bool {
		if ($url === ''
			|| strlen($url) > self::MAX_LENGTH
			|| $url[0] !== '/'
			|| str_starts_with($url, '//')
			|| str_contains($url, '\\')
			|| preg_match('/[\x00-\x1f\x7f]/', $url) !== 0) {
			return false;
		}
		foreach ($excluded as $path) {
			if (str_contains($url, $path)) {
				return false;
			}
		}
		return true;
	}
}
