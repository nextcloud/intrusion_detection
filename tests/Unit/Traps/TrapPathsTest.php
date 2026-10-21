<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Traps;

use OCA\IntrusionDetection\Traps\TrapPaths;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class TrapPathsTest extends TestCase {
	/**
	 * @return array<string, array{string, string, string}>
	 */
	public static function normalisation(): array {
		return [
			'plain' => ['/wp-login.php', '', '/wp-login.php'],
			'query and fragment' => ['/wp-login.php?redirect_to=x#top', '', '/wp-login.php'],
			'upper case' => ['/WP-Login.PHP', '', '/wp-login.php'],
			'repeated slashes' => ['//.git//config', '', '/.git/config'],
			'percent-encoded' => ['/%2Eenv', '', '/.env'],
			'below a web root' => ['/nextcloud/wp-admin/', '/nextcloud', '/wp-admin/'],
			'web root itself' => ['/nextcloud', '/nextcloud', '/'],
			'other folder than the web root' => ['/nextcloudx/.env', '/nextcloud', '/nextcloudx/.env'],
			'empty' => ['', '', '/'],
		];
	}

	#[DataProvider('normalisation')]
	public function testNormalise(string $uri, string $webRoot, string $expected): void {
		$this->assertSame($expected, TrapPaths::normalise($uri, $webRoot));
	}

	public function testVeryLongPathsAreCut(): void {
		$this->assertSame(TrapPaths::MAX_PATH, strlen(TrapPaths::normalise('/' . str_repeat('a', 100000), '')));
	}

	public function testTheRegexMatchesExactlyTheBuiltInList(): void {
		// preg_quote() also escapes "-", which is literal outside a character class anyway.
		$quoted = array_map(static fn (string $p): string => str_replace('\\-', '-', preg_quote($p, '#')), TrapPaths::BUILTIN);
		$expected = '#^(?:' . implode('|', $quoted) . ')#';
		$this->assertSame($expected, TrapPaths::BUILTIN_REGEX);
	}

	/**
	 * @return array<string, array{string, ?string}>
	 */
	public static function builtin(): array {
		return [
			'wordpress login' => ['/wp-login.php', '/wp-login.php'],
			'wordpress admin below' => ['/wp-admin/install.php', '/wp-admin'],
			'env file' => ['/.env', '/.env'],
			'env backup' => ['/.env.bak', '/.env'],
			'git config' => ['/.git/config', '/.git/'],
			'through the front controller' => ['/index.php/wp-login.php', '/wp-login.php'],
			'phpunit' => ['/vendor/phpunit/phpunit/src/util/php/eval-stdin.php', '/vendor/phpunit/'],
			'files app' => ['/apps/files/', null],
			'webdav' => ['/remote.php/dav/files/alice/.env', null],
			'a file called .env in webdav' => ['/remote.php/.env', null],
			'git without folder' => ['/.github', null],
			'login page' => ['/login', null],
			'status' => ['/status.php', null],
			'well-known caldav' => ['/.well-known/caldav', null],
			'autodiscover is off' => [TrapPaths::AUTODISCOVER, null],
		];
	}

	#[DataProvider('builtin')]
	public function testBuiltInMatches(string $path, ?string $trap): void {
		$this->assertSame($trap, TrapPaths::match($path, true, false, []));
	}

	public function testBuiltInCanBeSwitchedOff(): void {
		$this->assertNull(TrapPaths::match('/wp-login.php', false, false, []));
	}

	public function testAutodiscoverOnlyWhenSwitchedOn(): void {
		$this->assertSame(TrapPaths::AUTODISCOVER, TrapPaths::match(TrapPaths::AUTODISCOVER, true, true, []));
		$this->assertNull(TrapPaths::match('/autodiscover/other.xml', true, true, []));
	}

	public function testCustomPathsAreExactOrPrefixWithAStar(): void {
		$custom = ['/old-admin', '/secret-backup/*'];
		$this->assertSame('/old-admin', TrapPaths::match('/old-admin', false, false, $custom));
		$this->assertNull(TrapPaths::match('/old-admin/x', false, false, $custom));
		$this->assertSame('/secret-backup/*', TrapPaths::match('/secret-backup/db.sql', false, false, $custom));
		$this->assertNull(TrapPaths::match('/secret-backup', false, false, $custom));
	}

	/**
	 * @return array<string, array{string, bool}>
	 */
	public static function conflicts(): array {
		return [
			'root' => ['/', true],
			'everything' => ['/*', true],
			'apps' => ['/apps/foo', true],
			'covers apps and avatar' => ['/a*', true],
			'covers settings and status' => ['/s*', true],
			'front controller' => ['/index.php/foo', true],
			'well-known' => ['/.well-known/foo', true],
			'unrelated' => ['/old-admin', false],
			'unrelated prefix' => ['/wp*', false],
			'folder prefix' => ['/backup/*', false],
			'name starting like a segment' => ['/sadmin', false],
		];
	}

	#[DataProvider('conflicts')]
	public function testCustomPathsMustNotCoverNextcloud(string $entry, bool $conflicts): void {
		$this->assertSame($conflicts, TrapPaths::conflictsWithNextcloud($entry));
	}

	public function testNoBuiltInEntryTouchesANextcloudSegment(): void {
		foreach (TrapPaths::BUILTIN as $entry) {
			$this->assertFalse(TrapPaths::conflictsWithNextcloud(rtrim($entry, '/') . '*'), $entry);
		}
		$this->assertFalse(TrapPaths::conflictsWithNextcloud(TrapPaths::AUTODISCOVER));
	}

	/**
	 * @return array<string, array{string, bool}>
	 */
	public static function nextcloudPaths(): array {
		return [
			'root' => ['/', true],
			'an app' => ['/apps/files/', true],
			'the front controller' => ['/index.php/apps/files', true],
			'WebDAV' => ['/remote.php/dav/files/alice/.env', true],
			'a share link' => ['/s/aBcD', true],
			'a trap' => ['/.env', false],
			'a trap behind the front controller' => ['/index.php/.env', false],
			'the front controller alone' => ['/index.php', true],
			'a custom path' => ['/old-admin', false],
		];
	}

	#[DataProvider('nextcloudPaths')]
	public function testNextcloudPathsCanNeverBeATrap(string $path, bool $nextcloud): void {
		$this->assertSame($nextcloud, TrapPaths::isNextcloudPath($path));
		if ($nextcloud) {
			$this->assertNull(TrapPaths::match($path, true, true, ['/old-admin', '/backup/*']));
		}
	}

	/**
	 * @return array<string, array{string, string, bool}>
	 */
	public static function plainUris(): array {
		return [
			'WebDAV' => ['/remote.php/dav/files/alice/', '/', true],
			'an app under a web root' => ['/nextcloud/index.php/apps/files/', '/nextcloud', true],
			'a query' => ['/?x=1', '/', true],
			'a segment with a query' => ['/apps?x=1', '/', true],
			'upper case is normalised first' => ['/Remote.php/dav', '/', false],
			'encoded is normalised first' => ['/%72emote.php/dav', '/', false],
			'doubled slashes are normalised first' => ['//remote.php/dav', '/', false],
			'a trap behind doubled slashes' => ['//.env', '/', false],
			'a trap' => ['/.env', '/', false],
			'a trap behind the front controller' => ['/index.php/.env', '/', false],
			'a trap under a web root' => ['/nextcloud/wp-login.php', '/nextcloud', false],
		];
	}

	#[DataProvider('plainUris')]
	public function testPlainNextcloudUrisSkipTheNormalisation(string $uri, string $webRoot, bool $plain): void {
		$this->assertSame($plain, TrapPaths::isPlainNextcloudUri($uri, $webRoot));
		if ($plain) {
			$this->assertTrue(TrapPaths::isNextcloudPath(TrapPaths::normalise($uri, $webRoot)), 'Normalising would say the same');
		}
	}

	public function testNoBuiltInTrapIsANextcloudPath(): void {
		foreach ([...TrapPaths::BUILTIN, TrapPaths::AUTODISCOVER] as $entry) {
			$this->assertFalse(TrapPaths::isNextcloudPath($entry), $entry);
			$this->assertFalse(TrapPaths::isPlainNextcloudUri($entry, '/'), $entry);
			$this->assertFalse(TrapPaths::isNextcloudPath('/index.php' . $entry), $entry);
		}
	}
}
