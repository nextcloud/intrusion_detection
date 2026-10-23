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

	/** nginx with Nextcloud's documented configuration, which answers hidden paths such as /.env with "not found" */
	public const SERVER_NGINX = 'nginx';
	/** Apache with PHP-FPM, which answers a .php file that does not exist with "File not found." */
	public const SERVER_APACHE_FPM = 'apache_fpm';
	/** Apache with PHP in another way than PHP-FPM, or with pretty URLs: every unknown path reaches Nextcloud */
	public const SERVER_APACHE = 'apache';
	public const SERVER_UNKNOWN = 'unknown';

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
	/** The longest custom path */
	public const MAX_CUSTOM_LENGTH = 200;
	public const CUSTOM_PATTERN = '#^/[\x21-\x7e]{0,' . (self::MAX_CUSTOM_LENGTH - 1) . '}$#';

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
	 * Whether a normalised path is one of Nextcloud's own: its first segment
	 * (after `/index.php/`, if any) is one Nextcloud uses. No trap can match
	 * such a path: the built-in paths are none of them, and a custom path
	 * that would be one is refused ({@see conflictsWithNextcloud()}). Lets
	 * the common request skip reading the trap settings.
	 */
	public static function isNextcloudPath(string $path): bool {
		$candidate = str_starts_with($path, '/index.php/') ? substr($path, strlen('/index.php')) : $path;
		$segment = explode('/', substr($candidate, 1), 2)[0];
		return in_array($segment, self::NEXTCLOUD_SEGMENTS, true);
	}

	/**
	 * {@see isNextcloudPath()} for a request URI as it came, without
	 * normalising it: true only when its first segment is literally one of
	 * Nextcloud's, in lower case and not encoded, so that normalising could
	 * not change it. False means "normalise and look again", not "a trap".
	 */
	public static function isPlainNextcloudUri(string $requestUri, string $webRoot): bool {
		$webRoot = rtrim($webRoot, '/');
		if ($webRoot !== '' && $webRoot !== '.' && str_starts_with($requestUri, $webRoot . '/')) {
			$requestUri = substr($requestUri, strlen($webRoot));
		}
		if (str_starts_with($requestUri, '/index.php/')) {
			$requestUri = substr($requestUri, strlen('/index.php'));
		}
		if (!str_starts_with($requestUri, '/')) {
			return false;
		}
		$segment = substr($requestUri, 1, strcspn($requestUri, '/?#', 1));
		if ($segment === '' && ($requestUri[1] ?? '') === '/') {
			// Doubled slashes collapse: "//.env" is "/.env".
			return false;
		}
		return in_array($segment, self::NEXTCLOUD_SEGMENTS, true) && $segment === strtolower($segment);
	}

	/**
	 * The web servers that answer requests for a trap entry themselves, so
	 * they reach Nextcloud only with the rule of {@see TrapPathSnippets}.
	 * Every other unknown path reaches Nextcloud with the stock setups:
	 * Apache serves it Nextcloud's "not found" page through the ErrorDocument
	 * lines of Nextcloud's .htaccess, and the documented nginx configuration
	 * hands it to index.php.
	 *
	 * @return list<self::SERVER_NGINX|self::SERVER_APACHE_FPM>
	 */
	public static function answeredBy(string $entry): array {
		$path = rtrim($entry, '*');
		$servers = [];
		if (str_starts_with($path, '/.')) {
			$servers[] = self::SERVER_NGINX;
		}
		if (str_ends_with($path, '.php')) {
			$servers[] = self::SERVER_APACHE_FPM;
		}
		return $servers;
	}

	/**
	 * The enabled trap entries that reach Nextcloud on a web server only
	 * with the rule.
	 *
	 * @param list<string> $custom
	 * @return list<string>
	 */
	public static function needingRule(string $server, bool $builtin, bool $autodiscover, array $custom): array {
		$entries = array_merge($builtin ? self::BUILTIN : [], $autodiscover ? [self::AUTODISCOVER] : [], $custom);
		return array_values(array_filter($entries, static fn (string $entry): bool => in_array($server, self::answeredBy($entry), true)));
	}

	/**
	 * The web server setup that serves a request, from its SERVER_SOFTWARE,
	 * the PHP SAPI and whether Apache's pretty URLs are on. Behind a reverse
	 * proxy this is the server next to PHP, whose rules decide what reaches it.
	 *
	 * @return self::SERVER_*
	 */
	public static function webServer(string $software, string $sapi, bool $prettyUrls): string {
		$software = strtolower($software);
		if (str_starts_with($software, 'nginx')) {
			return self::SERVER_NGINX;
		}
		if (str_starts_with($software, 'apache')) {
			return $sapi === 'fpm-fcgi' && !$prettyUrls ? self::SERVER_APACHE_FPM : self::SERVER_APACHE;
		}
		return self::SERVER_UNKNOWN;
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
