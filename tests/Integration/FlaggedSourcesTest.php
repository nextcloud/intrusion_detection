<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\DB\ConnectionAdapter;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Login\EstablishedAccounts;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\ProtectedRanges;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanExemptions;
use OCA\IntrusionDetection\Response\Db\FlagMapper;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\ProxySuspect;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IDBConnection;
use OCP\IGroupManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The flags a password login reads: the password's and the address's, in
 * one query. Addresses many people share are not flagged.
 */
#[Group('DB')]
class FlaggedSourcesTest extends IntegrationTestCase {
	use CreatesAccounts;

	protected function tearDown(): void {
		$this->deleteAccounts();
		parent::tearDown();
	}

	public function testAnAddressManyPeopleLogInFromIsNotFlagged(): void {
		$source = SourceKey::fromIp('198.51.100.20');
		$hour = intdiv(time(), 3600);
		foreach ($this->accounts(5) as $uid) {
			Server::get(LoginMapper::class)->record($source->ipKey, $source->netKey, $uid, $hour);
		}
		$flags = Server::get(FlaggedSources::class);

		$this->assertNull($flags->flagSource($source, FlaggedSources::REASON_ATTACK));
		$this->assertFalse($flags->flagNetwork(SourceKey::fromIp('198.51.100.21'), FlaggedSources::REASON_USER_DENIED), 'its network neither');
		$this->assertNull($flags->sourceFlag($source));
		$this->assertNull($flags->sourceFlag(SourceKey::fromIp('198.51.100.21')));

		$other = SourceKey::fromIp('203.0.113.20');
		$this->assertNotNull($flags->flagSource($other, FlaggedSources::REASON_ATTACK), 'an address few people log in from is flagged');
		$this->assertSame(FlaggedSources::REASON_ATTACK, $flags->sourceFlag($other));
	}

	public function testANetworkOverTheAllowlistIsNotFlagged(): void {
		$this->appConfig->setValueString('bruteForce', 'whitelist_1', '192.0.2.200/32');
		try {
			$flags = new FlaggedSources(Server::get(FlagMapper::class), $this->freshExemptions(), Server::get(ITimeFactory::class));
			$this->assertFalse($flags->flagNetwork(SourceKey::fromIp('192.0.2.7'), FlaggedSources::REASON_USER_DENIED));
			$this->assertNull($flags->sourceFlag(SourceKey::fromIp('192.0.2.7')));
		} finally {
			$this->appConfig->deleteKey('bruteForce', 'whitelist_1');
		}
	}
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
		return new FlaggedSources(Server::get(FlagMapper::class), Server::get(BanExemptions::class), Server::get(ITimeFactory::class));
	}

	/**
	 * Exemptions with nothing cached from earlier tests (the allowlist is
	 * read once per instance).
	 */
	private function freshExemptions(): BanExemptions {
		return new BanExemptions(
			Server::get(LoginMapper::class),
			Server::get(LoginHistory::class),
			$this->appSettings(),
			Server::get(ProxySuspect::class),
			new ProtectedRanges($this->appConfig, Server::get(ServerAddresses::class)),
			Server::get(IGroupManager::class),
			Server::get(Caches::class),
			Server::get(EstablishedAccounts::class),
			Server::get(CheckRegistry::class),
		);
	}

	private function queries(): int {
		$connection = Server::get(IDBConnection::class);
		$this->assertInstanceOf(ConnectionAdapter::class, $connection);
		return $connection->getInner()->getStats()['executed'];
	}
}
