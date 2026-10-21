<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\BackgroundJob\FirewallExportJob;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Event\BanCreatedEvent;
use OCA\IntrusionDetection\Event\BanLiftedEvent;
use OCA\IntrusionDetection\Export\ExportDirectory;
use OCA\IntrusionDetection\Export\ExportException;
use OCA\IntrusionDetection\Export\FirewallExporter;
use OCA\IntrusionDetection\Listener\FirewallExportListener;
use OCA\IntrusionDetection\Net\ProtectedRanges;
use OCA\IntrusionDetection\Tests\Unit\Export\ExportDirectoryTest;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJobList;
use OCP\IConfig;
use OCP\Security\ISecureRandom;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

#[Group('DB')]
class FirewallExporterTest extends IntegrationTestCase {
	private int $now = 1792490400;
	private string $base;
	private ?string $exportDir;
	private Settings $settings;

	protected function setUp(): void {
		parent::setUp();
		$this->base = sys_get_temp_dir() . '/ids-exporter-' . bin2hex(random_bytes(4));
		mkdir($this->base . '/export', 0o750, true);
		$this->exportDir = $this->base . '/export';
		$this->settings = Server::get(Settings::class);
		$this->settings->setGlobal(GlobalSettings::EXPORT_FORMATS, ['txt', 'nft', 'ipset', 'log']);
	}

	protected function tearDown(): void {
		ExportDirectoryTest::remove($this->base);
		parent::tearDown();
	}

	public function testNothingIsWrittenWithoutAnExportDirectory(): void {
		$this->exportDir = null;
		$exporter = $this->exporter();
		$exporter->banChanged($this->ban('203.0.113.7/32', 3600), false);
		$this->assertFalse($exporter->writeIfDue());
		$this->assertSame(ExportException::NOT_CONFIGURED, $exporter->status()->error);
		$this->assertFalse($exporter->status()->isActive());
		$this->expectExceptionObject(new ExportException(ExportException::NOT_CONFIGURED));
		$exporter->write();
	}

	public function testNothingIsWrittenWithoutAFormat(): void {
		$this->settings->setGlobal(GlobalSettings::EXPORT_FORMATS, []);
		$this->exporter()->banChanged($this->ban('203.0.113.7/32', 3600), false);
		$this->assertSame([], $this->files());
	}

	public function testABlockIsExportedInEveryFormat(): void {
		$listener = new FirewallExportListener($this->exporter(), Server::get(LoggerInterface::class));
		$listener->handle(new BanCreatedEvent($this->ban('203.0.113.7/32', 14400, 'K7Q2MPXA')));
		$this->assertSame(['bans.log'], $this->files(), 'The request that blocked only appends the log line');
		$this->assertTrue($this->exporter()->writeIfDue(), 'The job writes the rest');

		$this->assertSame(['bans.ipset', 'bans.log', 'bans.nft', 'bans.txt'], $this->files());
		$this->assertStringContainsString("203.0.113.7/32 # until=2026-10-20T14:00:00Z ref=K7Q2MPXA\n", $this->read('bans.txt'));
		$this->assertStringContainsString('{ 203.0.113.7/32 timeout 14400s }', $this->read('bans.nft'));
		$this->assertStringContainsString("add nextcloud_ids_v4_new 203.0.113.7/32 timeout 14400\n", $this->read('bans.ipset'));
		$this->assertSame("2026-10-20T10:00:00Z BAN 203.0.113.7/32 until=2026-10-20T14:00:00Z level=1 check=trap_url ref=K7Q2MPXA\n", $this->read('bans.log'));
		$this->assertSame(0o640, fileperms($this->exportDir . '/bans.nft') & 0o777);

		$status = $this->exporter()->status();
		$this->assertNull($status->error);
		$this->assertSame($this->now, $status->lastWriteAt);
		$this->assertSame(1, $status->entries);
	}

	public function testALiftIsLoggedAndTheBlockLeavesTheFiles(): void {
		$ban = $this->ban('203.0.113.7/32', 14400, 'K7Q2MPXA');
		$exporter = $this->exporter();
		$exporter->banChanged($ban, false);
		$exporter->writeIfDue();
		$this->assertStringContainsString('203.0.113.7', $this->read('bans.txt'));

		$ban->setLiftedAt($this->now);
		Server::get(BanMapper::class)->update($ban);
		$this->now += 5;
		(new FirewallExportListener($this->exporter(), Server::get(LoggerInterface::class)))->handle(new BanLiftedEvent($ban));
		$this->assertTrue($this->exporter()->writeIfDue());

		$this->assertStringEndsWith("2026-10-20T10:00:05Z LIFT 203.0.113.7/32 ref=K7Q2MPXA\n", $this->read('bans.log'));
		$this->assertStringNotContainsString('203.0.113.7', $this->read('bans.txt'));
		$this->assertStringNotContainsString('203.0.113.7', $this->read('bans.nft'));
	}

	public function testFilesAreReplacedAtomicallyWithoutFollowingLinks(): void {
		$victim = $this->base . '/victim';
		file_put_contents($victim, 'untouched');
		symlink($victim, $this->exportDir . '/bans.txt');
		$this->ban('203.0.113.7/32', 3600);
		$this->exporter()->write();

		$this->assertFalse(is_link($this->exportDir . '/bans.txt'), 'The link is replaced, not followed');
		$this->assertSame('untouched', file_get_contents($victim));
		$this->assertSame([], glob($this->exportDir . '/.*.tmp') ?: [], 'No temporary file is left behind');
	}

	public function testEndedBlocksLeaveTheFilesAtTheNextJobRun(): void {
		$this->ban('203.0.113.7/32', 600);
		$this->ban('198.51.100.9/32', 7200);
		$exporter = $this->exporter();
		$exporter->write();
		$this->assertStringContainsString('203.0.113.7', $this->read('bans.txt'));

		$this->now += 300;
		$this->assertFalse($exporter->writeIfDue(), 'Nothing ended yet');

		$this->now += 301;
		$this->assertTrue($exporter->writeIfDue());
		$this->assertStringNotContainsString('203.0.113.7', $this->read('bans.txt'));
		$this->assertStringContainsString('198.51.100.9', $this->read('bans.txt'));
	}

	public function testTheJobDoesNothingWhenNothingChanged(): void {
		$this->ban('203.0.113.7/32', 3600);
		$exporter = $this->exporter();
		$exporter->write();
		$written = $this->read('bans.nft');
		touch($this->exportDir . '/bans.nft', 1000);
		clearstatcache();

		$this->now += 300;
		$job = new FirewallExportJob($this->time(), $exporter);
		$job->setLastRun(0);
		$job->start(Server::get(IJobList::class));

		clearstatcache();
		$this->assertSame(1000, filemtime($this->exportDir . '/bans.nft'), 'Not rewritten');
		$this->assertSame($written, $this->read('bans.nft'));
		$this->assertSame($this->now - 300, $exporter->status()->lastWriteAt);
	}

	public function testChangingTheFormatsRewritesAtTheNextJobRun(): void {
		$this->settings->setGlobal(GlobalSettings::EXPORT_FORMATS, ['txt']);
		$this->ban('203.0.113.7/32', 3600);
		$exporter = $this->exporter();
		$exporter->write();
		$this->assertSame(['bans.txt'], $this->files());

		$this->settings->setGlobal(GlobalSettings::EXPORT_FORMATS, ['txt', 'nft']);
		$this->assertTrue($exporter->writeIfDue());
		$this->assertSame(['bans.nft', 'bans.txt'], $this->files());
		$this->assertFalse($exporter->writeIfDue());
	}

	public function testEveryChangeOfTheBlocksIsWrittenAtTheNextJobRun(): void {
		$exporter = $this->exporter();
		$this->ban('203.0.113.7/32', 3600);
		$exporter->write();
		$this->assertFalse($exporter->writeIfDue());

		$ban = $this->ban('198.51.100.9/32', 3600);
		$this->assertTrue($exporter->writeIfDue(), 'A new block');
		$this->assertStringContainsString('198.51.100.9', $this->read('bans.txt'));
		$this->assertFalse($exporter->writeIfDue());

		$ban->setExpiresAt($ban->getExpiresAt() + 3600);
		Server::get(BanMapper::class)->update($ban);
		$this->assertTrue($exporter->writeIfDue(), 'A longer block');
		$this->assertStringContainsString('198.51.100.9/32 timeout 7200s', $this->read('bans.nft'));
	}

	public function testNothingIsExportedWhileProtectionIsOff(): void {
		$this->ban('203.0.113.7/32', 3600);
		$exporter = $this->exporter();
		$exporter->write();
		$this->assertStringContainsString('203.0.113.7', $this->read('bans.nft'));

		$this->settings->setGlobal(GlobalSettings::ENABLED, false);
		$this->assertTrue($exporter->writeIfDue(), 'Switching protection off rewrites the files');
		$this->assertStringNotContainsString('203.0.113.7', $this->read('bans.nft'));
		$this->assertStringNotContainsString('203.0.113.7', $this->read('bans.txt'));
		$this->assertSame(0, $exporter->status()->entries);
		$exporter->banChanged($this->ban('198.51.100.9/32', 3600), false);
		$this->assertFileDoesNotExist($this->exportDir . '/bans.log', 'Nothing is logged either');

		$this->settings->setGlobal(GlobalSettings::ENABLED, true);
		$this->assertTrue($exporter->writeIfDue(), 'And switching it on again');
		$this->assertStringContainsString('203.0.113.7', $this->read('bans.nft'));
	}

	public function testTheAllowlistAndTheServerAreNeverExported(): void {
		$this->appConfig->setValueString('bruteForce', 'whitelist_1', '198.51.100.7/32');
		$_SERVER['SERVER_ADDR'] = '198.51.100.250';
		try {
			$this->ban('198.51.100.7/32', 3600);
			$this->ban('198.51.100.0/24', 3600);
			$this->ban('127.0.0.1/32', 3600);
			$this->exporter()->write();
		} finally {
			unset($_SERVER['SERVER_ADDR']);
			$this->appConfig->deleteKey('bruteForce', 'whitelist_1');
		}
		$txt = $this->read('bans.txt');
		$this->assertStringNotContainsString('198.51.100.7/32', $txt);
		$this->assertStringNotContainsString('198.51.100.250/32', $txt);
		$this->assertStringNotContainsString('198.51.100.0/24', $txt, 'The /24 is split around them');
		$this->assertStringContainsString('198.51.100.128/26', $txt);
		$this->assertStringContainsString('198.51.100.8/29', $txt);
		$this->assertStringNotContainsString('127.0.0.1', $txt);
	}

	public function testTheExportCapKeepsTheLongestBlocks(): void {
		$this->ban('203.0.113.1/32', 600);
		$this->ban('203.0.113.2/32', 86400);
		$this->ban('203.0.113.3/32', 3600);
		$rows = Server::get(BanMapper::class)->findActiveForExport($this->now, 2);
		$this->assertSame(['203.0.113.2/32', '203.0.113.3/32'], array_column($rows, 'cidr'));
		$this->assertSame(['cidr', 'expires_at', 'reference', 'level', 'check_id'], array_keys($rows[0]), 'Plain columns only');
	}

	public function testTheLogIsRotatedAtTenMegabytes(): void {
		$log = $this->exportDir . '/bans.log';
		$handle = fopen($log, 'wb');
		ftruncate($handle, FirewallExporter::LOG_ROTATE_BYTES);
		fclose($handle);

		$this->exporter()->banChanged($this->ban('203.0.113.7/32', 3600, 'K7Q2MPXA'), false);

		$this->assertSame(FirewallExporter::LOG_ROTATE_BYTES, filesize($log . '.1'));
		$this->assertStringStartsWith('2026-10-20T10:00:00Z BAN 203.0.113.7/32 ', $this->read('bans.log'));
		$this->assertSame(1, substr_count($this->read('bans.log'), "\n"));
	}

	public function testAnUnusableDirectoryIsReportedNotThrownAtTheRequest(): void {
		chmod($this->exportDir, 0o777);
		$exporter = $this->exporter();
		$exporter->banChanged($this->ban('203.0.113.7/32', 3600), false);
		$this->assertSame(ExportException::WORLD_WRITABLE, $exporter->status()->error);
		$this->assertSame([], $this->files());

		chmod($this->exportDir, 0o750);
		$exporter->write();
		$this->assertNull($exporter->status()->error, 'A successful write clears the error');
	}

	private function ban(string $cidr, int $duration, string $reference = ''): Ban {
		$ban = new Ban();
		$ban->setReference($reference !== '' ? $reference : Server::get(ISecureRandom::class)->generate(8, 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'));
		$ban->setCidr($cidr);
		$ban->setScope(Ban::SCOPE_IP);
		$ban->setBanKey(explode('/', $cidr)[0]);
		$ban->setLevel(1);
		$ban->setCheckId('trap_url');
		$ban->setCreatedAt($this->now);
		$ban->setExpiresAt($this->now + $duration);
		return Server::get(BanMapper::class)->insert($ban);
	}

	private function exporter(): FirewallExporter {
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturnCallback(fn (string $key, string $default = ''): string => match ($key) {
			ExportDirectory::CONFIG_KEY => $this->exportDir ?? '',
			'datadirectory' => $this->base . '/data',
			default => $default,
		});
		$config->method('getSystemValue')->willReturn([]);
		return new FirewallExporter(
			new ExportDirectory($config),
			$this->settings,
			Server::get(BanMapper::class),
			new ProtectedRanges($this->appConfig),
			$this->time(),
			Server::get(ISecureRandom::class),
			Server::get(LoggerInterface::class),
		);
	}

	private function time(): ITimeFactory {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		return $time;
	}

	/**
	 * @return list<string>
	 */
	private function files(): array {
		if ($this->exportDir === null) {
			return array_values(array_diff(scandir($this->base . '/export') ?: [], ['.', '..']));
		}
		return array_values(array_diff(scandir($this->exportDir) ?: [], ['.', '..']));
	}

	private function read(string $file): string {
		return (string)file_get_contents($this->exportDir . '/' . $file);
	}
}
