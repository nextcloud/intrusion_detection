<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Traps;

use OCA\IntrusionDetection\Check\Checks\TrapUrl\TrapUrl;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCP\IURLGenerator;

/**
 * Web server snippets that hand requests for the trap paths to Nextcloud.
 *
 * Some trap paths never reach PHP: the documented nginx configuration
 * refuses hidden paths such as /.env, and Apache with PHP-FPM lets PHP-FPM
 * answer .php files that do not exist ({@see TrapPaths::answeredBy()}).
 * These snippets route exactly the enabled trap paths to index.php, which
 * keeps the original request URI, so the trap guard sees them.
 *
 * Only entries made of letters, digits and `/._~-` (plus a trailing `*`) are
 * put into a snippet, so an entry can never change the meaning of the web
 * server configuration; other entries are listed as left out.
 */
class TrapPathSnippets {
	private const SAFE_ENTRY = '#^/[a-z0-9/._~-]{0,199}\*?$#';

	public function __construct(
		private readonly CheckSettings $settings,
		private readonly IURLGenerator $urlGenerator,
	) {
	}

	/**
	 * @return array{nginx: array{file: string, content: string}, apache: array{file: string, content: string}, skipped: list<string>, paths: int}
	 */
	public function all(): array {
		[$pattern, $skipped, $count] = $this->pattern();
		$webRoot = rtrim($this->urlGenerator->getWebroot(), '/');
		if (preg_match('#^(/[A-Za-z0-9._~-]+)*$#', $webRoot) !== 1) {
			$webRoot = '';
		}
		return [
			'nginx' => ['file' => '/etc/nginx/sites-available/nextcloud', 'content' => $this->nginx($pattern, $webRoot)],
			'apache' => ['file' => '/etc/apache2/sites-available/nextcloud.conf', 'content' => $this->apache($pattern, $webRoot)],
			'skipped' => $skipped,
			'paths' => $count,
		];
	}

	/**
	 * One anchored pattern for the enabled trap paths: built-in and
	 * autodiscover entries and custom prefixes match as prefixes, other
	 * custom entries exactly. An empty string when no path is enabled.
	 *
	 * @return array{0: string, 1: list<string>, 2: int} the pattern, the left-out entries, the number of paths in it
	 */
	public function pattern(): array {
		$alternatives = [];
		if ($this->settings->paramBool(TrapUrl::ID, 'builtin_enabled')) {
			foreach (TrapPaths::BUILTIN as $path) {
				$alternatives[] = self::quote(substr($path, 1));
			}
		}
		if ($this->settings->paramBool(TrapUrl::ID, 'autodiscover')) {
			$alternatives[] = self::quote(substr(TrapPaths::AUTODISCOVER, 1));
		}
		$skipped = [];
		foreach ($this->settings->paramList(TrapUrl::ID, 'paths') as $entry) {
			if (preg_match(self::SAFE_ENTRY, $entry) !== 1) {
				$skipped[] = $entry;
				continue;
			}
			$alternatives[] = str_ends_with($entry, '*')
				? self::quote(substr($entry, 1, -1))
				: self::quote(substr($entry, 1)) . '$';
		}
		$alternatives = array_values(array_unique($alternatives));
		$pattern = $alternatives === [] ? '' : '/(?:' . implode('|', $alternatives) . ')';
		return [$pattern, $skipped, count($alternatives)];
	}

	private function nginx(string $pattern, string $webRoot): string {
		if ($pattern === '') {
			return "# No trap path is enabled, so there is nothing to route.\n";
		}
		$location = '^' . self::quote($webRoot) . $pattern;
		return <<<NGINX
			# Nextcloud intrusion detection: hand requests for trap paths to Nextcloud,
			# so that it can block the scanners sending them. Put this inside the
			# server block, before every other "location ~" block.
			location ~* "{$location}" {
				rewrite ^ {$webRoot}/index.php\$request_uri last;
			}

			NGINX;
	}

	private function apache(string $pattern, string $webRoot): string {
		if ($pattern === '') {
			return "# No trap path is enabled, so there is nothing to route.\n";
		}
		$rule = '^' . self::quote($webRoot) . $pattern;
		return <<<APACHE
			# Nextcloud intrusion detection: hand requests for trap paths to Nextcloud,
			# so that it can block the scanners sending them. Put this into the
			# VirtualHost of Nextcloud (not into .htaccess), with mod_rewrite enabled.
			RewriteEngine On
			RewriteRule "{$rule}" "{$webRoot}/index.php" [NC,PT,L]

			APACHE;
	}

	/**
	 * Escape a safe entry for a regular expression: only `.` has a meaning there.
	 */
	private static function quote(string $path): string {
		return str_replace('.', '\.', $path);
	}
}
