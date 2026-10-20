<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanResult;
use OCA\IntrusionDetection\Response\BanService;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

#[Group('DB')]
class BanServiceTest extends IntegrationTestCase {
	private BanService $bans;
	private BanMapper $mapper;

	protected function setUp(): void {
		parent::setUp();
		$this->bans = Server::get(BanService::class);
		$this->mapper = Server::get(BanMapper::class);
	}

	public function testFirstBanIsLevelOneForFourHours(): void {
		$result = $this->bans->ban(SourceKey::fromIp('198.51.100.7'), 'trap_url');
		$this->assertSame(BanResult::BANNED, $result->outcome);
		$this->assertNotNull($result->ban);
		$this->assertSame(1, $result->ban->getLevel());
		$this->assertSame('198.51.100.7/32', $result->ban->getCidr());
		$this->assertSame(Ban::SCOPE_IP, $result->ban->getScope());
		$this->assertEqualsWithDelta(time() + 14400, $result->ban->getExpiresAt(), 5);
		$this->assertMatchesRegularExpression('/^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/', $result->ban->getDisplayReference());
	}

	public function testRepeatOffendersEscalate(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$this->insertEndedBan($source->ipKey, time() - 5 * 86400);
		$second = $this->bans->ban($source, 'trap_url');
		$this->assertSame(2, $second->ban?->getLevel());
		$this->assertEqualsWithDelta(time() + 86400, $second->ban?->getExpiresAt(), 5);

		$this->bans->lift($second->ban, 'test', 'next round');
		$third = $this->bans->ban($source, 'trap_url');
		$this->assertSame(3, $third->ban?->getLevel());
		$this->assertEqualsWithDelta(time() + 604800, $third->ban?->getExpiresAt(), 5);
	}

	public function testBansOutsideTheHistoryWindowDoNotEscalate(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$this->insertEndedBan($source->ipKey, time() - 31 * 86400);
		$this->assertSame(1, $this->bans->ban($source, 'trap_url')->ban?->getLevel());
	}

	public function testAnotherCheckOfTheSameAttackDoesNotEscalateAnActiveBan(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$first = $this->bans->ban($source, 'credential_stuffing');
		$again = $this->bans->ban($source, 'password_spraying');
		$this->assertSame(BanResult::ALREADY, $again->outcome);
		$this->assertSame($first->ban?->getId(), $again->ban?->getId());
		$this->assertSame(1, $again->ban?->getLevel());
	}

	public function testAForcedHigherLevelRaisesAnActiveBan(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$first = $this->bans->ban($source, 'trap_url');
		$raised = $this->bans->ban($source, 'decoy_credential', forceLevel: 3);
		$this->assertSame(BanResult::EXTENDED, $raised->outcome);
		$this->assertSame($first->ban?->getId(), $raised->ban?->getId());
		$this->assertSame(3, $raised->ban?->getLevel());
		$this->assertEqualsWithDelta(time() + 604800, $raised->ban?->getExpiresAt(), 5);
	}

	public function testThirdAddressInASlash24BlocksTheNetwork(): void {
		$this->bans->ban(SourceKey::fromIp('198.51.100.1'), 'trap_url');
		$second = $this->bans->ban(SourceKey::fromIp('198.51.100.2'), 'trap_url');
		$this->assertNull($second->netBan);
		$third = $this->bans->ban(SourceKey::fromIp('198.51.100.3'), 'trap_url');
		$this->assertNotNull($third->netBan);
		$this->assertSame('198.51.100.0/24', $third->netBan->getCidr());
		$this->assertSame(Ban::SCOPE_NET, $third->netBan->getScope());

		// A fourth address finds the network already blocked and adds no second network ban.
		$fourth = $this->bans->ban(SourceKey::fromIp('198.51.100.4'), 'trap_url');
		$this->assertNull($fourth->netBan);
	}

	public function testIpv6IsAlwaysBlockedAsTheSlash64(): void {
		$result = $this->bans->ban(SourceKey::fromIp('2001:db8:1:2::7'), 'trap_url');
		$this->assertSame('2001:db8:1:2::/64', $result->ban?->getCidr());
		$this->assertSame(Ban::SCOPE_NET, $result->ban?->getScope());
		$again = $this->bans->ban(SourceKey::fromIp('2001:db8:1:2:ffff::1'), 'trap_url');
		$this->assertSame(BanResult::ALREADY, $again->outcome);
	}

	public function testSafetyValveKeepsSharedAddressesUnblocked(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$logins = Server::get(LoginMapper::class);
		$hour = intdiv(time(), 3600);
		foreach (['alice', 'bob', 'carol', 'dave', 'erin'] as $uid) {
			$logins->record($source->ipKey, $source->netKey, $uid, $hour);
		}
		$result = $this->bans->ban($source, 'credential_stuffing');
		$this->assertSame(BanResult::SKIPPED_SHARED, $result->outcome);
		$this->assertSame(5, $result->sharedUsers);
		$this->assertSame([], $this->mapper->findActiveForKeys([$source->ipKey], time()));
	}

	public function testSafetyValveCountsTheNetworkToo(): void {
		$logins = Server::get(LoginMapper::class);
		$hour = intdiv(time(), 3600);
		foreach (['alice', 'bob', 'carol', 'dave', 'erin'] as $i => $uid) {
			$other = SourceKey::fromIp('198.51.100.' . (10 + $i));
			$logins->record($other->ipKey, $other->netKey, $uid, $hour);
		}
		$this->assertSame(BanResult::SKIPPED_SHARED, $this->bans->ban(SourceKey::fromIp('198.51.100.99'), 'trap_url')->outcome);
	}

	public function testSafetyValveCanBeTurnedOff(): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::BAN_SHARED_IP_USERS, 0);
		$source = SourceKey::fromIp('198.51.100.7');
		$logins = Server::get(LoginMapper::class);
		foreach (['alice', 'bob', 'carol', 'dave', 'erin'] as $uid) {
			$logins->record($source->ipKey, $source->netKey, $uid, intdiv(time(), 3600));
		}
		$this->assertSame(BanResult::BANNED, $this->bans->ban($source, 'trap_url')->outcome);
	}

	public function testLoopbackIsNeverBlocked(): void {
		$this->assertSame(BanResult::SKIPPED_NEVER, $this->bans->ban(SourceKey::fromIp('127.0.0.1'), 'trap_url')->outcome);
		$this->assertSame(BanResult::SKIPPED_NEVER, $this->bans->ban(SourceKey::fromIp('::1'), 'trap_url')->outcome);
	}

	public function testLiftEndsTheBanAndInvalidatesTheCache(): void {
		$result = $this->bans->ban(SourceKey::fromIp('198.51.100.7'), 'trap_url');
		$versionBefore = $this->appConfig->getValueInt(Application::APP_ID, GlobalSettings::BAN_VERSION);
		$this->bans->lift($result->ban, 'admin', 'false alarm');
		$this->assertGreaterThan($versionBefore, $this->appConfig->getValueInt(Application::APP_ID, GlobalSettings::BAN_VERSION));
		$stored = $this->mapper->findById($result->ban->getId());
		$this->assertNotNull($stored->getLiftedAt());
		$this->assertSame('admin', $stored->getLiftedBy());
		$this->assertSame('false alarm', $stored->getLiftNote());
		$this->assertFalse($stored->isActive(time()));
	}

	public function testManualBansAcceptAddressesAndNetworksOnly(): void {
		$this->assertSame('203.0.113.7/32', $this->bans->banManually('203.0.113.7', 1, 'admin', 'test')->getCidr());
		$this->assertSame('203.0.113.0/24', $this->bans->banManually('203.0.113.50/24', 1, 'admin', null)->getCidr());
		$this->assertSame('2001:db8:9::/64', $this->bans->banManually('2001:db8:9::1', 1, 'admin', null)->getCidr());
		$this->expectException(\InvalidArgumentException::class);
		$this->bans->banManually('203.0.0.0/16', 1, 'admin', null);
	}

	public function testReferencesAreUniqueAndFoundInAnyCase(): void {
		$ban = $this->bans->ban(SourceKey::fromIp('198.51.100.7'), 'trap_url')->ban;
		$typed = strtolower($ban->getDisplayReference());
		$this->assertSame($ban->getId(), $this->mapper->findByReference($typed)->getId());
		$this->assertSame($ban->getId(), $this->mapper->findByReference(str_replace('-', '', $typed))->getId());
	}

	private function insertEndedBan(string $banKey, int $createdAt): void {
		$ban = new Ban();
		$ban->setReference(substr(str_shuffle('ABCDEFGHJKLMNPQRSTUVWXYZ23456789'), 0, 8));
		$ban->setCidr($banKey . '/32');
		$ban->setScope(Ban::SCOPE_IP);
		$ban->setBanKey($banKey);
		$ban->setLevel(1);
		$ban->setCheckId('trap_url');
		$ban->setCreatedAt($createdAt);
		$ban->setExpiresAt($createdAt + 14400);
		$this->mapper->insert($ban);
	}
}
