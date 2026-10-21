<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\DB\ConnectionAdapter;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\FlagMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IDBConnection;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The flags a password login reads: the password's and the address's, in
 * one query.
 */
#[Group('DB')]
class FlaggedSourcesTest extends IntegrationTestCase {
	public function testALoginReadsThePasswordAndAddressFlagsInOneQuery(): void {
		$flags = $this->flags();
		$source = SourceKey::fromIp('203.0.113.5');
		$flags->flagPassword('aa11');
		$flags->flagNetwork($source, FlaggedSources::REASON_ATTACK);

		$before = $this->queries();
		$this->assertTrue($flags->loginFlags($source, ['bb22', 'aa11']));
		$this->assertSame(FlaggedSources::REASON_ATTACK, $flags->sourceFlag($source));
		$this->assertSame(1, $this->queries() - $before, 'The flagged-source reason reuses the login\'s read');

		$this->assertFalse($flags->loginFlags(SourceKey::fromIp('198.51.100.5'), ['bb22']));
		$this->assertNull($flags->sourceFlag(SourceKey::fromIp('198.51.100.5')));
	}

	public function testANewFlagIsSeenInTheSameRequest(): void {
		$flags = $this->flags();
		$source = SourceKey::fromIp('203.0.113.6');
		$this->assertFalse($flags->loginFlags($source, []));
		$this->assertNull($flags->sourceFlag($source));
		$flags->flagSource($source, FlaggedSources::REASON_USER_DENIED);
		$this->assertSame(FlaggedSources::REASON_USER_DENIED, $flags->sourceFlag($source));
		$flags->unflagSource($source);
		$this->assertNull($flags->sourceFlag($source));
	}

	private function flags(): FlaggedSources {
		return new FlaggedSources(Server::get(FlagMapper::class), Server::get(Settings::class), Server::get(ITimeFactory::class));
	}

	private function queries(): int {
		$connection = Server::get(IDBConnection::class);
		$this->assertInstanceOf(ConnectionAdapter::class, $connection);
		return $connection->getInner()->getStats()['executed'];
	}
}
