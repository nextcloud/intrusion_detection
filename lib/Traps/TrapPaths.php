<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Traps;

/**
 * Paths no legitimate Nextcloud client ever requests, and how a request path
 * is normalised before it is compared with them.
 *
 * - The built-in list is matched by prefix with one anchored regular
 *   expression without nested quantifiers (BUILTIN_REGEX). A unit test keeps
 *   it equal to BUILTIN and checks that no entry touches a Nextcloud route.
 * - Custom paths are exact, or a prefix when they end with "*".
 * - Paths whose first segment Nextcloud itself uses (NEXTCLOUD_SEGMENTS)
 *   cannot be added, so a typo cannot block legitimate clients.
 */
final class TrapPaths {
	/** @var list<string> */
	public const BUILTIN = [
		'/wp-login.php', '/wp-admin', '/xmlrpc.php', '/.env', '/.git/', '/.aws/', '/phpmyadmin', '/pma',
		'/adminer.php', '/vendor/phpunit/', '/cgi-bin/', '/boaform/', '/hnap1', '/actuator/', '/server-status',
		'/config.json', '/.ds_store', '/owa/', '/ecp/',
	];

	/** BUILTIN as one anchored prefix match */
	public const BUILTIN_REGEX = '#^(?:/wp-login\.php|/wp-admin|/xmlrpc\.php|/\.env|/\.git/|/\.aws/|/phpmyadmin|/pma|/adminer\.php|/vendor/phpunit/|/cgi-bin/|/boaform/|/hnap1|/actuator/|/server-status|/config\.json|/\.ds_store|/owa/|/ecp/)#';

	/** Requested by some mail clients that probe for Exchange, so only trapped when switched on */
	public const AUTODISCOVER = '/autodiscover/autodiscover.xml';

	/**
	 * First path segments Nextcloud uses itself: entry points, routes,
	 * well-known URLs and static folders. A test checks that every route's
	 * first segment is listed here.
	 *
	 * @var list<string>
	 */
	public const NEXTCLOUD_SEGMENTS = [
		'', '204', '.well-known', 'apps', 'apps-extra', 'avatar', 'contactsmenu', 'core', 'cron.php', 'csrftoken',
		'css', 'custom_apps', 'dist', 'displaynames', 'error', 'f', 'favicon.ico', 'heartbeat', 'index.html',
		'index.php', 'js', 'l10n', 'login', 'logout', 'lostpassword', 'metrics', 'ocm', 'ocm-provider', 'ocs',
		'ocs-provider', 'ocsapp', 'public.php', 'remote.php', 'resources', 'robots.txt', 's', 'settings',
		'status.php', 'themes', 'u', 'unsupported', 'updater',
	];

	public const MAX_PATH = 1024;
	public const MAX_CUSTOM = 100;
	public const CUSTOM_PATTERN = '#^/[\x21-\x7e]{0,199}$#';

	/**
	 * The path of a request URI relative to the web root: without query and
	 * fragment, percent-decoded once, repeated slashes collapsed, lower-cased.
	 */
	public static function normalise(string $requestUri, string $webRoot): string {
		$path = $requestUri;
		$cut = strcspn($path, '?#');
		$path = substr($path, 0, min($cut, self::MAX_PATH * 3));
		$path = strtolower(rawurldecode($path));
		$path = (string)preg_replace('#/{2,}#', '/', $path);
		$webRoot = rtrim(strtolower($webRoot), '/');
		if ($webRoot !== '' && ($path === $webRoot || str_starts_with($path, $webRoot . '/'))) {
			$path = substr($path, strlen($webRoot));
		}
		if ($path === '' || $path[0] !== '/') {
			$path = '/' . $path;
		}
		return substr($path, 0, self::MAX_PATH);
	}

	/**
	 * The paths to compare: the path itself, and without a leading
	 * "/index.php", since Nextcloud's front controller serves both.
	 *
	 * @return list<string>
	 */
	public static function candidates(string $path): array {
		if (str_starts_with($path, '/index.php/')) {
			return [$path, substr($path, strlen('/index.php'))];
		}
		return [$path];
	}

	/**
	 * Which trap a normalised path hits, if any: the built-in entry, the
	 * autodiscover path or the custom entry.
	 *
	 * @param list<string> $custom
	 */
	public static function match(string $path, bool $builtin, bool $autodiscover, array $custom): ?string {
		foreach (self::candidates($path) as $candidate) {
			if ($builtin && preg_match(self::BUILTIN_REGEX, $candidate, $m) === 1) {
				return $m[0];
			}
			if ($autodiscover && $candidate === self::AUTODISCOVER) {
				return self::AUTODISCOVER;
			}
			foreach ($custom as $entry) {
				if (str_ends_with($entry, '*') ? str_starts_with($candidate, substr($entry, 0, -1)) : $candidate === $entry) {
					return $entry;
				}
			}
		}
		return null;
	}

	/**
	 * Whether a custom entry is, or covers, a path Nextcloud itself uses.
	 */
	public static function conflictsWithNextcloud(string $entry): bool {
		$entry = strtolower($entry);
		if (str_starts_with($entry, '/index.php')) {
			return true;
		}
		$prefix = str_ends_with($entry, '*');
		$path = ltrim($prefix ? substr($entry, 0, -1) : $entry, '/');
		$segment = explode('/', $path, 2)[0];
		$isWholeSegment = str_contains($path, '/');
		foreach (self::NEXTCLOUD_SEGMENTS as $reserved) {
			if ($segment === $reserved || ($prefix && !$isWholeSegment && str_starts_with($reserved, $segment))) {
				return true;
			}
		}
		return false;
	}
}
