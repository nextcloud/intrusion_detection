<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Export;

use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Export\ExportEntry;
use OCA\IntrusionDetection\Export\ExportFormat;
use OCA\IntrusionDetection\Export\ExportRenderer;
use OCA\IntrusionDetection\Export\FirewallSnippets;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

/**
 * The export files, compared with golden files in tests/fixtures/export.
 */
class ExportRendererTest extends TestCase {
	/** 2026-10-20T10:00:00Z */
	public const NOW = 1792490400;

	/**
	 * The blocks the golden files were made from.
	 *
	 * @return list<Ban>
	 */
	public static function bans(): array {
		return [
			self::ban('203.0.113.7/32', self::NOW + 14400, 'K7Q2MPXA', 1, 'trap_url'),
			self::ban('2001:db8:1:2::/64', self::NOW + 604800, 'W6HB3RTZ', 3, 'decoy_credential'),
			self::ban('198.51.100.7/32', self::NOW + 86400, 'P4CDEF9G', 2, 'credential_stuffing'),
			self::ban('198.51.100.0/24', self::NOW + 3600, 'N8XYZ2QR', 2, 'credential_stuffing'),
			self::ban('192.0.2.1/32', self::NOW + 90 * 86400, 'M5MANUAL', 1, 'manual'),
		];
	}

	/**
	 * @return array<string, array{ExportFormat}>
	 */
	public static function snapshotFormats(): array {
		return ['txt' => [ExportFormat::Txt], 'nft' => [ExportFormat::Nft], 'ipset' => [ExportFormat::Ipset]];
	}

	#[DataProvider('snapshotFormats')]
	public function testMatchesTheGoldenFile(ExportFormat $format): void {
		$this->assertSame(
			file_get_contents(__DIR__ . '/../../fixtures/export/' . $format->fileName()),
			ExportRenderer::render($format, self::entries(), self::NOW),
		);
	}

	public function testNftablesLeavesOutAddressesInsideABlockedNetwork(): void {
		$nft = ExportRenderer::nft(self::entries(), self::NOW);
		$this->assertStringContainsString('198.51.100.0/24 timeout 3600s', $nft);
		$this->assertStringNotContainsString('198.51.100.7', $nft);
		// ipset sets accept overlapping ranges, so both stay there.
		$this->assertStringContainsString('198.51.100.7/32', ExportRenderer::ipset(self::entries(), self::NOW));
	}

	public function testIpsetTimeoutsAreCappedAtTheLongestIpsetAccepts(): void {
		$this->assertStringContainsString('add nextcloud_ids_v4_new 192.0.2.1/32 timeout ' . ExportRenderer::IPSET_MAX_TIMEOUT . "\n", ExportRenderer::ipset(self::entries(), self::NOW));
		$this->assertStringContainsString('192.0.2.1/32 timeout ' . (90 * 86400) . 's', ExportRenderer::nft(self::entries(), self::NOW));
	}

	public function testAnEmptyExportStillResetsTheSets(): void {
		$nft = ExportRenderer::nft([], self::NOW);
		$this->assertStringContainsString("flush set inet nextcloud_ids banned_v4\n", $nft);
		$this->assertStringNotContainsString('add element', $nft);
		$ipset = ExportRenderer::ipset([], self::NOW);
		$this->assertStringContainsString("swap nextcloud_ids_v6_new nextcloud_ids_v6\n", $ipset);
	}

	public function testTheLoadersAcceptEveryLineTheAppWrites(): void {
		foreach ([[ExportFormat::Nft, FirewallSnippets::NFT_LINE_PATTERN], [ExportFormat::Ipset, FirewallSnippets::IPSET_LINE_PATTERN]] as [$format, $pattern]) {
			foreach ([self::entries(), []] as $entries) {
				$lines = explode("\n", rtrim(ExportRenderer::render($format, $entries, self::NOW), "\n"));
				foreach ($lines as $line) {
					$this->assertMatchesRegularExpression('/' . str_replace('/', '\/', $pattern) . '/', $line);
				}
			}
		}
	}

	/**
	 * @return array<string, array{string, string}>
	 */
	public static function foreignLines(): array {
		return [
			'nft: flush everything' => [FirewallSnippets::NFT_LINE_PATTERN, 'flush ruleset'],
			'nft: other table' => [FirewallSnippets::NFT_LINE_PATTERN, 'add element inet filter allowed { 0.0.0.0/0 timeout 1s }'],
			'nft: second command on the line' => [FirewallSnippets::NFT_LINE_PATTERN, 'add element inet nextcloud_ids banned_v4 { 192.0.2.1 timeout 1s }; flush ruleset'],
			'nft: delete a table' => [FirewallSnippets::NFT_LINE_PATTERN, 'delete table inet filter'],
			'nft: include' => [FirewallSnippets::NFT_LINE_PATTERN, 'include "/etc/passwd"'],
			'nft: chain in our table' => [FirewallSnippets::NFT_LINE_PATTERN, "\tchain input { type filter hook input priority 0; policy drop; }"],
			'ipset: other set' => [FirewallSnippets::IPSET_LINE_PATTERN, 'flush whitelist'],
			'ipset: destroy live set' => [FirewallSnippets::IPSET_LINE_PATTERN, 'destroy nextcloud_ids_v4'],
			'ipset: swap with another set' => [FirewallSnippets::IPSET_LINE_PATTERN, 'swap nextcloud_ids_v4_new whitelist'],
		];
	}

	#[DataProvider('foreignLines')]
	public function testTheLoadersRefuseAnythingElse(string $pattern, string $line): void {
		$this->assertDoesNotMatchRegularExpression('/' . str_replace('/', '\/', $pattern) . '/', $line);
	}

	public function testLogLinesHaveTheDocumentedFormat(): void {
		$ban = self::ban('203.0.113.7/32', self::NOW + 14400, 'K7Q2MPXA', 1, 'trap_url');
		$this->assertSame(
			"2026-10-20T10:00:00Z BAN 203.0.113.7/32 until=2026-10-20T14:00:00Z level=1 check=trap_url ref=K7Q2MPXA\n",
			ExportRenderer::banLine($ban, self::NOW),
		);
		$this->assertSame("2026-10-20T11:00:00Z LIFT 203.0.113.7/32 ref=K7Q2MPXA\n", ExportRenderer::liftLine($ban, self::NOW + 3600));
	}

	/**
	 * @return list<ExportEntry>
	 */
	public static function entries(): array {
		return ExportEntry::sort(array_map(static fn (Ban $b): ExportEntry => ExportEntry::fromBan($b), self::bans()));
	}

	public static function ban(string $cidr, int $expiresAt, string $reference, int $level, string $checkId): Ban {
		$ban = new Ban();
		$ban->setCidr($cidr);
		$ban->setExpiresAt($expiresAt);
		$ban->setReference($reference);
		$ban->setLevel($level);
		$ban->setCheckId($checkId);
		return $ban;
	}
}
