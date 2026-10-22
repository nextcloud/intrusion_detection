<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Response;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Login\EstablishedAccounts;
use OCA\IntrusionDetection\Net\ProtectedRanges;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanExemptions;
use OCA\IntrusionDetection\Response\BanResult;
use OCA\IntrusionDetection\Response\ProxySuspect;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\IGroupManager;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class BanExemptionsTest extends TestCase {
	private LoginMapper&MockObject $logins;
	private LoginHistoryMapper&MockObject $history;
	private ProxySuspect&MockObject $proxies;
	private IGroupManager&MockObject $groups;

	protected function setUp(): void {
		parent::setUp();
		$this->logins = $this->createMock(LoginMapper::class);
		$this->history = $this->createMock(LoginHistoryMapper::class);
		$this->proxies = $this->createMock(ProxySuspect::class);
		$this->groups = $this->createMock(IGroupManager::class);
		$this->groups->method('isAdmin')->willReturnCallback(static fn (string $uid): bool => $uid === 'admin');
	}

	public function testTheFactsOfAnAddressAreRememberedForAMinute(): void {
		$this->logins->expects($this->once())->method('distinctUidsForIp')->willReturn(['a', 'b', 'c', 'd', 'e', 'f']);
		$this->history->expects($this->once())->method('acceptedUidsFrom')->willReturn([]);
		$exemptions = $this->exemptions(new ArrayCache('ids-test'));
		$source = SourceKey::fromIp('198.51.100.7');
		for ($i = 0; $i < 3; $i++) {
			$result = $exemptions->forAddress($source, time(), 'trap_url');
			$this->assertSame(BanResult::SKIPPED_SHARED, $result?->outcome);
			$this->assertSame(6, $result->sharedUsers);
		}
	}

	public function testWithoutAMemoryCacheEveryBlockAsks(): void {
		$this->logins->expects($this->exactly(2))->method('distinctUidsForIp')->willReturn([]);
		$exemptions = $this->exemptions(null);
		$exemptions->forAddress(SourceKey::fromIp('198.51.100.7'), time(), 'trap_url');
		$exemptions->forAddress(SourceKey::fromIp('198.51.100.7'), time(), 'trap_url');
	}

	public function testTheRememberedFactsServeEveryCheck(): void {
		$this->history->expects($this->once())->method('acceptedUidsFrom')->willReturn(['alice', 'admin']);
		$exemptions = $this->exemptions(new ArrayCache('ids-test'));
		$source = SourceKey::fromIp('198.51.100.7');
		$this->assertNull($exemptions->forAddress($source, time(), 'trap_url'), 'No login exempts from a trap');
		$this->assertSame(BanResult::SKIPPED_TRUSTED, $exemptions->forAddress($source, time(), 'credential_stuffing')?->outcome, 'An administrator logged in from it');
	}

	public function testOnlyTheAccountOfTheDetectionIsAskedForAConfirmedLogin(): void {
		$this->history->method('acceptedUidsFrom')->willReturn(['alice']);
		$this->history->expects($this->once())->method('hasConfirmedLogin')->with('alice')->willReturn(true);
		$exemptions = $this->exemptions(null);
		$source = SourceKey::fromIp('198.51.100.7');
		$this->assertNull($exemptions->forAddress($source, time(), 'credential_stuffing', 'alice'), 'Not a check about one account');
		$this->assertSame(BanResult::SKIPPED_TRUSTED, $exemptions->forAddress($source, time(), 'account_under_attack', 'alice')?->outcome);
	}

	public function testAHeldBackAddressIsReportedOncePerMinute(): void {
		$exemptions = $this->exemptions(new ArrayCache('ids-test'));
		$this->assertTrue($exemptions->firstReport(SourceKey::fromIp('198.51.100.7')));
		$this->assertFalse($exemptions->firstReport(SourceKey::fromIp('198.51.100.7')));
		$this->assertTrue($exemptions->firstReport(SourceKey::fromIp('198.51.100.8')));
		$this->assertTrue($this->exemptions(null)->firstReport(SourceKey::fromIp('198.51.100.7')), 'Without a memory cache every time');
	}

	private function exemptions(?ArrayCache $cache): BanExemptions {
		$settings = $this->createMock(AppSettings::class);
		$settings->method('banSharedIpUsers')->willReturn(5);
		$factory = new FixedCaches(null, $cache);
		$accounts = $this->createMock(EstablishedAccounts::class);
		$accounts->method('count')->willReturnCallback(static fn (array $uids): int => count($uids));
		return new BanExemptions($this->logins, $this->history, $settings, $this->proxies, $this->createMock(ProtectedRanges::class), $this->groups, $factory, $accounts, Server::get(CheckRegistry::class));
	}
}
