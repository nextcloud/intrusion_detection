<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Command\Blocklists\ListBlocklists;
use OCA\IntrusionDetection\Command\Blocklists\Set;
use OCA\IntrusionDetection\Command\Blocklists\Sync;
use OCA\IntrusionDetection\Command\Export\Write;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Export\ExportDirectory;
use OCA\IntrusionDetection\Export\ExportException;
use OCA\IntrusionDetection\Export\FirewallExporter;
use OCA\IntrusionDetection\Net\ProtectedRanges;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\Security\ISecureRandom;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

#[Group('DB')]
class BlocklistCommandsTest extends IntegrationTestCase {
	public function testSetSwitchesAListOnAndChangesItsInterval(): void {
		$tester = new CommandTester(Server::get(Set::class));
		$this->assertSame(Command::SUCCESS, $tester->execute(['id' => 'tor_exits', '--enable' => true, '--interval' => '2h']));
		$this->assertStringContainsString('tor_exits is on', $tester->getDisplay());
		$source = Server::get(SourceRepository::class)->get('tor_exits');
		$this->assertTrue($source?->enabled);
		$this->assertSame(7200, $source?->interval);

		$this->assertSame(Command::SUCCESS, $tester->execute(['id' => 'tor_exits', '--disable' => true, '--interval' => 'default']));
		$this->assertFalse(Server::get(SourceRepository::class)->get('tor_exits')?->enabled);
		$this->assertSame(3600, Server::get(SourceRepository::class)->get('tor_exits')?->interval);
	}

	public function testSetRefusesALocalAddressWithAnExplanation(): void {
		$tester = new CommandTester(Server::get(Set::class));
		$this->assertSame(Command::INVALID, $tester->execute(['id' => 'mine', '--url' => 'https://127.0.0.1/list.txt', '--purpose' => 'deny']));
		$this->assertStringContainsString('outside the local network', $tester->getDisplay());
		$this->assertNull(Server::get(SourceRepository::class)->get('mine'));
	}

	public function testSetAddsAndRemovesACustomList(): void {
		$tester = new CommandTester(Server::get(Set::class));
		$this->assertSame(Command::SUCCESS, $tester->execute(['id' => 'mine', '--url' => 'https://lists.example.org/x.txt', '--purpose' => 'hosting', '--enable' => true]));
		$this->assertSame('hosting', Server::get(SourceRepository::class)->get('mine')?->purpose);
		$this->assertSame(Command::SUCCESS, $tester->execute(['id' => 'mine', '--remove' => true]));
		$this->assertNull(Server::get(SourceRepository::class)->get('mine'));
	}

	public function testListShowsEveryListWithItsReference(): void {
		$tester = new CommandTester(Server::get(ListBlocklists::class));
		$this->assertSame(Command::SUCCESS, $tester->execute(['--matches' => true]));
		$display = $tester->getDisplay();
		$this->assertStringContainsString('spamhaus_drop_v4', $display);
		$this->assertStringContainsString('tor_exits', $display);
		$this->assertStringContainsString(Server::get(SourceRepository::class)->reference('firehol_level1'), $display);

		$this->assertSame(Command::SUCCESS, $tester->execute(['--output' => 'json']));
		$this->assertCount(count(Server::get(SourceRepository::class)->all()), json_decode($tester->getDisplay(), true));
	}

	public function testSyncWithoutListsAndWithAnUnknownList(): void {
		$tester = new CommandTester(Server::get(Sync::class));
		$this->assertSame(Command::SUCCESS, $tester->execute([]));
		$this->assertStringContainsString('No list is enabled.', $tester->getDisplay());
		$this->assertSame(Command::INVALID, $tester->execute(['id' => 'nope']));
	}

	public function testExportWriteExplainsWhatIsMissing(): void {
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturnArgument(1);
		$exporter = new FirewallExporter(
			new ExportDirectory($config),
			Server::get(Settings::class),
			Server::get(BanMapper::class),
			Server::get(ProtectedRanges::class),
			Server::get(ITimeFactory::class),
			Server::get(ISecureRandom::class),
			Server::get(LoggerInterface::class),
		);
		$tester = new CommandTester(new Write($exporter));
		$this->assertSame(Command::FAILURE, $tester->execute([]));
		$this->assertStringContainsString('No export format is switched on', $tester->getDisplay());

		Server::get(Settings::class)->setGlobal(GlobalSettings::EXPORT_FORMATS, ['nft']);
		$this->assertSame(Command::FAILURE, $tester->execute([]));
		$this->assertStringContainsString(Write::describe(ExportException::NOT_CONFIGURED), $tester->getDisplay());
	}
}
