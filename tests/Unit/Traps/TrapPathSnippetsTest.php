<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Traps;

use OCA\IntrusionDetection\Check\Checks\TrapUrl\TrapUrl;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Traps\TrapPaths;
use OCA\IntrusionDetection\Traps\TrapPathSnippets;
use OCP\IURLGenerator;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class TrapPathSnippetsTest extends TestCase {
	/**
	 * @param list<string> $custom
	 */
	private function snippets(bool $builtin, bool $autodiscover, array $custom, string $webRoot = ''): TrapPathSnippets {
		$settings = $this->createMock(CheckSettings::class);
		$settings->method('paramBool')->willReturnMap([
			[TrapUrl::ID, 'builtin_enabled', $builtin],
			[TrapUrl::ID, 'autodiscover', $autodiscover],
		]);
		$settings->method('paramList')->with(TrapUrl::ID, 'paths')->willReturn($custom);
		$urls = $this->createMock(IURLGenerator::class);
		$urls->method('getWebroot')->willReturn($webRoot);
		return new TrapPathSnippets($settings, $urls);
	}

	public static function paths(): array {
		return [
			'built-in prefix' => ['/wp-login.php', true],
			'built-in prefix, longer path' => ['/.git/config', true],
			'own exact path' => ['/backup.zip', true],
			'own exact path is not a prefix' => ['/backup.zip.old', false],
			'own prefix' => ['/old-admin/users', true],
			'autodiscover' => ['/autodiscover/autodiscover.xml', true],
			'a Nextcloud path' => ['/index.php/apps/files', false],
			'a dot is a dot' => ['/wp-loginXphp', false],
		];
	}

	#[DataProvider('paths')]
	public function testThePatternMatchesWhatTheGuardTraps(string $path, bool $trapped): void {
		[$pattern] = $this->snippets(true, true, ['/backup.zip', '/old-admin/*'])->pattern();
		$this->assertSame($trapped, preg_match('#^' . $pattern . '#i', $path) === 1);
		$this->assertSame($trapped, TrapPaths::match($path, true, true, ['/backup.zip', '/old-admin/*']) !== null, 'Same as the guard');
	}

	public function testEntriesThatCouldChangeTheConfigurationAreLeftOut(): void {
		[$pattern, $skipped, $count] = $this->snippets(false, false, ['/ok-path', '/a"b', '/a{1,9}', '/x;y', '/semi$'])->pattern();
		$this->assertSame(['/a"b', '/a{1,9}', '/x;y', '/semi$'], $skipped);
		$this->assertSame('/(?:ok-path$)', $pattern);
		$this->assertSame(1, $count);
	}

	public function testSnippetsUseTheWebRoot(): void {
		$all = $this->snippets(false, false, ['/old/*'], '/cloud')->all();
		$this->assertStringContainsString('location ~* "^/cloud/(?:old/)"', $all['nginx']['content']);
		$this->assertStringContainsString('rewrite ^ /cloud/index.php$request_uri last;', $all['nginx']['content']);
		$this->assertStringContainsString('RewriteRule "^/cloud/(?:old/)" "/cloud/index.php" [NC,PT,L]', $all['apache']['content']);
	}

	public function testAWebRootThatNeedsQuotingIsNotUsed(): void {
		$all = $this->snippets(false, false, ['/old/*'], '/my cloud')->all();
		$this->assertStringContainsString('"^/(?:old/)"', $all['nginx']['content']);
	}

	public function testNothingToRoute(): void {
		$all = $this->snippets(false, false, [])->all();
		$this->assertSame(0, $all['paths']);
		$this->assertStringStartsWith('# No trap path is enabled', $all['nginx']['content']);
		$this->assertStringStartsWith('# No trap path is enabled', $all['apache']['content']);
	}
}
