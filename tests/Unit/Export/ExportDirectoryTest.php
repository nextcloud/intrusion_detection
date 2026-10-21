<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Export;

use OCA\IntrusionDetection\Export\ExportDirectory;
use OCA\IntrusionDetection\Export\ExportException;
use OCP\IConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class ExportDirectoryTest extends TestCase {
	private string $base;

	protected function setUp(): void {
		parent::setUp();
		$this->base = sys_get_temp_dir() . '/ids-export-' . bin2hex(random_bytes(4));
		mkdir($this->base . '/data/alice/files', 0o750, true);
		mkdir($this->base . '/export', 0o750);
		mkdir($this->base . '/open', 0o777);
		chmod($this->base . '/open', 0o777);
		touch($this->base . '/file');
		symlink($this->base . '/data/alice', $this->base . '/link-into-data');
	}

	protected function tearDown(): void {
		self::remove($this->base);
		parent::tearDown();
	}

	public static function remove(string $path): void {
		if (is_link($path) || is_file($path)) {
			unlink($path);
			return;
		}
		if (!is_dir($path)) {
			return;
		}
		foreach (scandir($path) ?: [] as $entry) {
			if ($entry !== '.' && $entry !== '..') {
				self::remove($path . '/' . $entry);
			}
		}
		rmdir($path);
	}

	public function testAWritableDirectoryOutsideDataAndInstallationIsAccepted(): void {
		$this->assertSame(realpath($this->base . '/export'), $this->directory($this->base . '/export')->resolve());
	}

	/**
	 * @return array<string, array{?string, string}>
	 */
	public static function refused(): array {
		$serverRoot = dirname(__DIR__, 5);
		return [
			'not set' => [null, ExportException::NOT_CONFIGURED],
			'empty' => ['  ', ExportException::NOT_CONFIGURED],
			'relative' => ['export', ExportException::NOT_ABSOLUTE],
			'missing' => ['{base}/missing', ExportException::NOT_FOUND],
			'a file' => ['{base}/file', ExportException::NOT_A_DIRECTORY],
			'the data directory' => ['{base}/data', ExportException::INSIDE_DATA_DIRECTORY],
			'a user folder' => ['{base}/data/alice/files', ExportException::INSIDE_DATA_DIRECTORY],
			'a link into the data directory' => ['{base}/link-into-data', ExportException::INSIDE_DATA_DIRECTORY],
			'the installation' => [$serverRoot, ExportException::INSIDE_WEB_ROOT],
			'inside the installation' => [$serverRoot . '/apps/intrusion_detection', ExportException::INSIDE_WEB_ROOT],
			'a parent of the installation' => [dirname($serverRoot), ExportException::INSIDE_WEB_ROOT],
			'the file system root' => ['/', ExportException::INSIDE_WEB_ROOT],
			'world-writable' => ['{base}/open', ExportException::WORLD_WRITABLE],
		];
	}

	#[DataProvider('refused')]
	public function testUnsafeDirectoriesAreRefused(?string $dir, string $reason): void {
		try {
			$this->directory($dir === null ? null : str_replace('{base}', $this->base, $dir))->resolve();
			$this->fail('Expected ' . $reason);
		} catch (ExportException $e) {
			$this->assertSame($reason, $e->reason);
		}
	}

	public function testAnAppsDirectoryElsewhereIsRefused(): void {
		mkdir($this->base . '/custom_apps/export', 0o750, true);
		$directory = $this->directory($this->base . '/custom_apps/export', [['path' => $this->base . '/custom_apps', 'url' => '/custom_apps', 'writable' => true]]);
		$this->expectExceptionObject(new ExportException(ExportException::INSIDE_WEB_ROOT));
		$directory->resolve();
	}

	public function testANotWritableDirectoryIsRefused(): void {
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root can write everywhere');
		}
		chmod($this->base . '/export', 0o550);
		try {
			$this->directory($this->base . '/export')->resolve();
			$this->fail('Expected not_writable');
		} catch (ExportException $e) {
			$this->assertSame(ExportException::NOT_WRITABLE, $e->reason);
		} finally {
			chmod($this->base . '/export', 0o750);
		}
	}

	/**
	 * @param list<array<string, mixed>> $appsPaths
	 */
	private function directory(?string $dir, array $appsPaths = []): ExportDirectory {
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturnCallback(fn (string $key, string $default = ''): string => match ($key) {
			ExportDirectory::CONFIG_KEY => $dir ?? $default,
			'datadirectory' => $this->base . '/data',
			default => $default,
		});
		$config->method('getSystemValue')->willReturnCallback(static fn (string $key, mixed $default = ''): mixed => $key === 'apps_paths' ? $appsPaths : $default);
		return new ExportDirectory($config);
	}
}
