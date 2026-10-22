<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check\Checks\InjectionProbe;

use OCA\IntrusionDetection\Check\Checks\InjectionProbe\RequestParts;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class RequestPartsTest extends TestCase {
	/**
	 * @return array<string, array{string, ?string, bool}>
	 */
	public static function paths(): array {
		return [
			'WebDAV files' => ['/remote.php/dav/files/alice/Bob\'s union select.txt', '/remote.php', true],
			'legacy WebDAV' => ['/remote.php/webdav/Bob\'s.txt', '/remote.php', true],
			'calendars' => ['/remote.php/dav/calendars/alice/personal/x.ics', '/remote.php', true],
			'public WebDAV' => ['/public.php/dav/files/token/x\'.txt', '/public.php', true],
			'legacy public WebDAV' => ['/public.php/webdav/x\'.txt', '/public.php', true],
			'in a sub folder' => ['/nextcloud/remote.php/dav/files/alice/x\'.txt', '/nextcloud/remote.php', true],
			'derived from the URL' => ['/nextcloud/remote.php/dav/files/alice/x\'.txt', null, true],
			'Files thumbnails' => ['/index.php/apps/files/api/v1/thumbnail/32/32/x\'.jpg', '/index.php', true],
			'Files thumbnails with pretty URLs' => ['/apps/files/api/v1/thumbnail/32/32/x\'.jpg', '/index.php', true],
			'an app route' => ['/index.php/apps/foo/1\' or 1=1', '/index.php', false],
			'a WebDAV-looking path on index.php' => ['/index.php/apps/foo/remote.php/dav/files/x\'', '/index.php', false],
			'remote.php outside WebDAV' => ['/remote.php/direct/abc\'', '/remote.php', false],
			'a lookalike root' => ['/remote.php/davx/abc\'', '/remote.php', false],
		];
	}

	#[DataProvider('paths')]
	public function testFilePathsAreExcluded(string $path, ?string $script, bool $excluded): void {
		$parts = RequestParts::fromUri($path . '?id=1', $script);
		$this->assertSame($excluded, $parts->pathExcluded);
		$this->assertSame($excluded ? '' : $path, $parts->path);
		$this->assertSame('id=1', $parts->query, 'The query string is inspected either way');
	}

	public function testSearchRoutes(): void {
		$this->assertTrue(RequestParts::fromUri('/ocs/v2.php/search/providers/files/search?q=x', '/ocs/v2.php')->isSearchRoute());
		$this->assertTrue(RequestParts::fromUri('/ocs/v2.php/core/autocomplete/get?search=x', '/ocs/v2.php')->isSearchRoute());
		$this->assertFalse(RequestParts::fromUri('/index.php/apps/foo?q=x', '/index.php')->isSearchRoute());
	}

	public function testFragmentIsNotPartOfTheQuery(): void {
		$this->assertSame('a=1', RequestParts::fromUri('/x?a=1#frag', '/index.php')->query);
	}
}
