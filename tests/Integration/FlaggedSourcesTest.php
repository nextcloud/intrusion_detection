<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\DB\ConnectionAdapter;
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

	public function testTheRiskScoreReusesTheFlagsALoginRead(): void {
		$flags = $this->flags();
		$source = SourceKey::fromIp('203.0.113.7');
		$flags->flagAttackTool($source, 'hydra');
		$flags->flagSource($source, FlaggedSources::REASON_ATTACK);

		$before = $this->queries();
		$flags->loginFlags($source, ['cc33']);
		$this->assertSame(['tool' => 'hydra', 'source' => FlaggedSources::REASON_ATTACK], $flags->riskFlags($source));
		$this->assertSame(1, $this->queries() - $before, 'one read of the flags per login');

		$flags->unflagSource($source);
		$this->assertSame(['tool' => 'hydra', 'source' => null], $flags->riskFlags($source), 'a changed flag is read again');
		$this->assertSame(['tool' => null, 'source' => null], $this->flags()->riskFlags(SourceKey::fromIp('198.51.100.9')));
	}

	public function testAFlagThatLastsLongEnoughCostsOneReadAndNoWrite(): void {
		$mapper = Server::get(FlagMapper::class);
		$now = Server::get(ITimeFactory::class)->getTime();
		$this->assertTrue($mapper->flag('tool:4:203.0.113.8', 'hydra', $now + 86400, null, $now));

		$before = $this->queries();
		$this->assertFalse($mapper->flag('tool:4:203.0.113.8', 'hydra', $now + 86400 + 60, null, $now + 60));
		$this->assertSame(1, $this->queries() - $before, 'one read, no update and no insert');

		$before = $this->queries();
		$this->assertTrue($mapper->flag('tool:4:203.0.113.8', 'nmap', $now + 3 * 86400, null, $now + 2 * 86400));
		$this->assertSame(2, $this->queries() - $before, 'a read and the update');
		$this->assertSame(['tool:4:203.0.113.8' => 'nmap'], $mapper->active(['tool:4:203.0.113.8'], $now + 2 * 86400));

		$before = $this->queries();
		$this->assertTrue($mapper->flag('tool:4:203.0.113.9', 'hydra', $now + 86400, null, $now));
		$this->assertSame(2, $this->queries() - $before, 'a read and the insert');
	}

	private function flags(): FlaggedSources {
		return new FlaggedSources(Server::get(FlagMapper::class), Server::get(ITimeFactory::class));
	}

	private function queries(): int {
		$connection = Server::get(IDBConnection::class);
		$this->assertInstanceOf(ConnectionAdapter::class, $connection);
		return $connection->getInner()->getStats()['executed'];
	}
}
