<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Export;

use OCP\IConfig;
use OCP\Server;

/**
 * The directory the firewall export writes to: `intrusion_detection.export_dir`
 * in config.php. It is never set from the web interface, because that would
 * let a web administrator write files anywhere the web server can.
 *
 * The directory is checked before every write:
 * - It must be an absolute path to an existing directory (symbolic links are
 *   resolved first, so the checks apply to the real location).
 * - It must not be inside the data directory: that holds the users' files and
 *   app data, and a file there could appear in someone's files or overwrite
 *   app data.
 * - It must not be inside the Nextcloud installation or an apps directory,
 *   nor contain the installation: those are served by the web server, so the
 *   list of blocked addresses (personal data) would be public, and a parent
 *   of the installation is usually the web server's document root. Other
 *   folders the web server serves cannot be known here; the documentation
 *   asks for a folder outside every web root.
 * - It must not be world-writable: a root-owned firewall loader reads these
 *   files, so no other local user may be able to place or swap them.
 * - It must be writable by the web server user.
 */
class ExportDirectory {
	public const CONFIG_KEY = 'intrusion_detection.export_dir';

	public function __construct(
		private readonly IConfig $config,
	) {
	}

	public function configured(): ?string {
		$dir = trim($this->config->getSystemValueString(self::CONFIG_KEY, ''));
		return $dir === '' ? null : $dir;
	}

	/**
	 * The real path of the export directory, after all checks.
	 *
	 * @throws ExportException
	 */
	public function resolve(): string {
		$dir = $this->configured() ?? throw new ExportException(ExportException::NOT_CONFIGURED);
		if (!str_starts_with($dir, '/') || str_contains($dir, "\0")) {
			throw new ExportException(ExportException::NOT_ABSOLUTE);
		}
		$real = realpath($dir);
		if ($real === false) {
			throw new ExportException(ExportException::NOT_FOUND);
		}
		if (!is_dir($real)) {
			throw new ExportException(ExportException::NOT_A_DIRECTORY);
		}
		$dataDir = $this->config->getSystemValueString('datadirectory', '');
		$dataDir = $dataDir === '' ? false : realpath($dataDir);
		if ($dataDir !== false && self::isWithin($real, $dataDir)) {
			throw new ExportException(ExportException::INSIDE_DATA_DIRECTORY);
		}
		foreach ($this->servedPaths() as $served) {
			if (self::isWithin($real, $served) || self::isWithin($served, $real)) {
				throw new ExportException(ExportException::INSIDE_WEB_ROOT);
			}
		}
		$perms = @fileperms($real);
		if ($perms === false || ($perms & 0o002) !== 0) {
			throw new ExportException(ExportException::WORLD_WRITABLE);
		}
		if (!is_writable($real)) {
			throw new ExportException(ExportException::NOT_WRITABLE);
		}
		return $real;
	}

	/**
	 * Whether `$path` is `$base` or below it.
	 */
	public static function isWithin(string $path, string $base): bool {
		$base = rtrim($base, '/');
		return $path === $base || $base === '' || str_starts_with($path, $base . '/');
	}

	/**
	 * The installation and every apps directory, resolved.
	 *
	 * @return list<string>
	 */
	private function servedPaths(): array {
		// Core's public API is <installation>/lib/public, wherever the apps are.
		$paths = [dirname((string)(new \ReflectionClass(Server::class))->getFileName(), 3)];
		$appsPaths = $this->config->getSystemValue('apps_paths', []);
		if (is_array($appsPaths)) {
			foreach ($appsPaths as $entry) {
				if (is_array($entry) && is_string($entry['path'] ?? null)) {
					$paths[] = $entry['path'];
				}
			}
		}
		$resolved = [];
		foreach ($paths as $path) {
			$real = realpath($path);
			if ($real !== false) {
				$resolved[] = $real;
			}
		}
		return $resolved;
	}
}
