<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\InjectionProbe;

/**
 * The parts of a request the injection probe check looks at: the path
 * (empty when it is a file path), the raw query string and the form fields.
 *
 * File and folder names are never inspected: a file can legitimately be
 * called `Bob's "union select" notes.txt`. That covers the whole WebDAV tree
 * of remote.php and public.php, and the Files app routes that carry a path.
 * The script name comes from the web server, not from the client, so a
 * client cannot hide a payload behind a WebDAV-looking path.
 */
final class RequestParts {
	/** Below these, everything on remote.php and public.php is a file, calendar or contact name */
	private const DAV_ROOTS = ['/dav', '/webdav', '/caldav', '/carddav'];
	/** Routes of index.php whose path carries a file path */
	private const FILE_PATH_ROUTES = ['/apps/files/api/v1/thumbnail/', '/apps/files/api/v1/files/'];

	/**
	 * @param array<array-key, mixed> $post form fields as PHP parsed them
	 * @param string $route the path below the script, for the route-specific rules
	 */
	public function __construct(
		public readonly string $path,
		public readonly string $query,
		public readonly array $post,
		public readonly bool $pathExcluded,
		public readonly string $route = '',
	) {
	}

	/**
	 * @param string $uri the request URI as sent: path and query string
	 * @param ?string $scriptName the PHP script that serves the request, as the web server reports it; null to derive it from the URI
	 * @param array<array-key, mixed> $post
	 */
	public static function fromUri(string $uri, ?string $scriptName, array $post = []): self {
		[$path, $query] = self::split($uri);
		$scriptName ??= self::scriptFromPath($path);
		$route = self::routePath($path, $scriptName);
		$slash = strrpos($scriptName, '/');
		$excluded = self::isFilePath($slash === false ? $scriptName : substr($scriptName, $slash + 1), $route);
		return new self($excluded ? '' : $path, $query, $post, $excluded, $route);
	}

	/**
	 * The whole URI, without excluding file paths: for a first pre-filter
	 * pass that needs no knowledge of the script. Nothing it lets through
	 * would be caught with the exclusions applied.
	 *
	 * @param array<array-key, mixed> $post
	 */
	public static function unfiltered(string $uri, array $post = []): self {
		[$path, $query] = self::split($uri);
		return new self($path, $query, $post, false);
	}

	/**
	 * @return array{0: string, 1: string} path and query string, without a fragment
	 */
	private static function split(string $uri): array {
		$mark = strpos($uri, '?');
		if ($mark === false) {
			return [$uri, ''];
		}
		$query = substr($uri, $mark + 1);
		$hash = strpos($query, '#');
		return [substr($uri, 0, $mark), $hash === false ? $query : substr($query, 0, $hash)];
	}

	/**
	 * Whether the request goes to a search or autocomplete route, where `q`
	 * is free text.
	 */
	public function isSearchRoute(): bool {
		return stripos($this->route, 'search') !== false || stripos($this->route, 'autocomplete') !== false;
	}

	/**
	 * The path below the script (or below the web root for pretty URLs without index.php).
	 */
	private static function routePath(string $path, string $scriptName): string {
		if ($scriptName !== '' && str_starts_with($path, $scriptName)) {
			return substr($path, strlen($scriptName));
		}
		$root = rtrim(dirname($scriptName === '' ? '/' : $scriptName), '/');
		return $root !== '' && str_starts_with($path, $root . '/') ? substr($path, strlen($root)) : $path;
	}

	private static function isFilePath(string $script, string $route): bool {
		// Encoded characters would let `/d%61v/` look different from what the server serves.
		if (str_contains($route, '%')) {
			$route = rawurldecode($route);
		}
		if ($script === 'remote.php' || $script === 'public.php') {
			foreach (self::DAV_ROOTS as $root) {
				if ($route === $root || str_starts_with($route, $root . '/')) {
					return true;
				}
			}
			return false;
		}
		if ($script === 'index.php') {
			foreach (self::FILE_PATH_ROUTES as $prefix) {
				if (str_starts_with($route, $prefix)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * For URLs pasted into "Test a URL": the first `*.php` segment, or index.php.
	 */
	private static function scriptFromPath(string $path): string {
		if (preg_match('~^(.*?/(?:remote|public|index|cron|status)\.php)(?=/|$)~', $path, $m) === 1) {
			return $m[1];
		}
		if (preg_match('~^(.*?/ocs/v[12]\.php)(?=/|$)~', $path, $m) === 1) {
			return $m[1];
		}
		return '/index.php';
	}
}
