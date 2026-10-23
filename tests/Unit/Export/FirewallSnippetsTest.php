<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Export;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Export\ExportDirectory;
use OCA\IntrusionDetection\Export\ExportRenderer;
use OCA\IntrusionDetection\Export\FirewallSnippets;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class FirewallSnippetsTest extends TestCase {
	/**
	 * fail2ban's `<SUBNET>` tag: an IPv4 or IPv6 address with an optional
	 * prefix length (fail2ban/server/failregex.py, R_HOST[RI_SUBNET]).
	 */
	private const SUBNET = '\[?(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)(?:/\d{1,3})?\]?';

	public function testTheFilterContainsTheTestedExpressions(): void {
		$filter = $this->snippets('/srv/nextcloud-ids')->fail2banFilter();
		$this->assertStringContainsString('failregex = ' . FirewallSnippets::FAIL2BAN_FAILREGEX . "\n", $filter);
		$this->assertStringContainsString('datepattern = ' . FirewallSnippets::FAIL2BAN_DATEPATTERN . "\n", $filter);
		$this->assertStringContainsString("[Definition]\n", $filter);
	}

	/**
	 * @return array<string, array{string, ?string}>
	 */
	public static function logLines(): array {
		$ban = ExportRendererTest::ban(...);
		$now = ExportRendererTest::NOW;
		return [
			'IPv4 address' => [ExportRenderer::banLine($ban('203.0.113.7/32', $now + 14400, 'K7Q2MPXA', 1, 'trap_url'), $now), '203.0.113.7/32'],
			'IPv4 network' => [ExportRenderer::banLine($ban('198.51.100.0/24', $now + 3600, 'N8XYZ2QR', 3, 'credential_stuffing'), $now), '198.51.100.0/24'],
			'IPv6 network' => [ExportRenderer::banLine($ban('2001:db8:1:2::/64', $now + 3600, 'W6HB3RTZ', 2, 'decoy_credential'), $now), '2001:db8:1:2::/64'],
			'a lift is not a ban' => [ExportRenderer::liftLine($ban('203.0.113.7/32', $now, 'K7Q2MPXA', 1, 'trap_url'), $now), null],
			'a forged line with more after the reference' => ['2026-10-20T10:00:00Z BAN 203.0.113.7/32 until=x level=1 check=trap_url ref=AAAA extra', null],
		];
	}

	/**
	 * Applies the filter as fail2ban does: the time stamp matched by the
	 * datepattern is removed, then the failregex runs on the rest of the line
	 * with `<SUBNET>` expanded.
	 */
	#[DataProvider('logLines')]
	public function testTheFail2banFilterMatchesTheLogLines(string $line, ?string $subnet): void {
		$line = rtrim($line, "\n");
		$date = '/^' . strtr(FirewallSnippets::FAIL2BAN_DATEPATTERN, [
			'{^LN-BEG}' => '',
			'%%Y' => '\d{4}', '%%m' => '\d{2}', '%%d' => '\d{2}', '%%H' => '\d{2}', '%%M' => '\d{2}', '%%S' => '\d{2}',
		]) . '/';
		$this->assertMatchesRegularExpression($date, $line, 'The time stamp is recognised');
		$rest = (string)preg_replace($date, '', $line, 1);

		$regex = '#' . str_replace('<SUBNET>', '(?<subnet>' . self::SUBNET . ')', FirewallSnippets::FAIL2BAN_FAILREGEX) . '#';
		$matched = preg_match($regex, $rest, $m);
		if ($subnet === null) {
			$this->assertSame(0, $matched);
		} else {
			$this->assertSame(1, $matched);
			$this->assertSame($subnet, $m['subnet']);
		}
	}

	public function testSnippetsUseTheConfiguredDirectory(): void {
		$snippets = $this->snippets('/srv/nextcloud-ids/');
		$this->assertTrue($snippets->usesConfiguredDirectory());
		$all = $snippets->all();
		$this->assertStringContainsString("file='/srv/nextcloud-ids/bans.nft'", $all['nft_loader']['content']);
		$this->assertStringContainsString('PathChanged=/srv/nextcloud-ids/bans.nft', $all['systemd_path']['content']);
		$this->assertStringContainsString('logpath  = /srv/nextcloud-ids/bans.log', $all['fail2ban_jail']['content']);
		$this->assertStringContainsString('bantime  = 14400', $all['fail2ban_jail']['content']);
		$this->assertStringContainsString("grep -Evq '" . FirewallSnippets::NFT_LINE_PATTERN . "'", $all['nft_loader']['content']);
		$this->assertStringContainsString("grep -Evq '" . FirewallSnippets::IPSET_LINE_PATTERN . "'", $all['ipset']['content']);
		$this->assertStringContainsString('set banned_v4', $all['nftables']['content']);
	}

	/**
	 * @return array<string, array{?string}>
	 */
	public static function unusableDirectories(): array {
		return ['none' => [null], 'space' => ['/srv/next cloud'], 'quote' => ["/srv/it's"], 'shell' => ['/srv/$(reboot)']];
	}

	#[DataProvider('unusableDirectories')]
	public function testAPathThatNeedsQuotingIsReplacedByTheExample(?string $dir): void {
		$snippets = $this->snippets($dir);
		$this->assertFalse($snippets->usesConfiguredDirectory());
		foreach ($snippets->all() as $snippet) {
			if ($dir !== null) {
				$this->assertStringNotContainsString($dir, $snippet['content']);
			}
		}
		$this->assertStringContainsString(FirewallSnippets::EXAMPLE_DIR . '/bans.nft', $snippets->nftLoader());
	}

	public function testThePatternsHaveNoSingleQuotes(): void {
		// They are embedded in single-quoted shell strings.
		$this->assertStringNotContainsString("'", FirewallSnippets::NFT_LINE_PATTERN);
		$this->assertStringNotContainsString("'", FirewallSnippets::IPSET_LINE_PATTERN);
	}

	private function snippets(?string $dir): FirewallSnippets {
		$directory = $this->createMock(ExportDirectory::class);
		$directory->method('configured')->willReturn($dir);
		$settings = $this->createMock(AppSettings::class);
		$settings->method('banDurations')->willReturn([1 => 14400, 2 => 86400, 3 => 604800]);
		return new FirewallSnippets($directory, $settings);
	}
}
