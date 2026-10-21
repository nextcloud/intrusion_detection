<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\BackgroundJob\Cleanup;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\KeyLock;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Db\StateMapper;
use OCA\IntrusionDetection\Event\TypedEvents;
use OCA\IntrusionDetection\Net\ProtectedRanges;
use OCA\IntrusionDetection\Net\ProxySuspect;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanExemptions;
use OCA\IntrusionDetection\Response\BanRefusedException;
use OCA\IntrusionDetection\Response\BanResult;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ICacheFactory;
use OCP\IConfig;
use OCP\IGroupManager;
use OCP\IRequest;
use OCP\Lock\ILockingProvider;
use OCP\Lock\LockedException;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Security\ISecureRandom;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
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

	public function testANetworkCanBeBlockedAsAWhole(): void {
		$result = $this->bans->banNetwork(SourceKey::fromIp('198.51.100.7'), 'credential_stuffing', 5);
		$this->assertSame(BanResult::BANNED, $result->outcome);
		$this->assertSame('198.51.100.0/24', $result->ban?->getCidr());
		$this->assertSame(Ban::SCOPE_NET, $result->ban?->getScope());
		$this->assertSame(1, $result->ban?->getLevel());
		$this->assertSame(BanResult::ALREADY, $this->bans->banNetwork(SourceKey::fromIp('198.51.100.99'), 'credential_stuffing')->outcome);
		$this->assertSame(BanResult::SKIPPED_NEVER, $this->bans->banNetwork(SourceKey::fromIp('2001:db8::1'), 'credential_stuffing')->outcome, 'Only an IPv4 /24');
	}

	public function testANetworkBlockedAsAWholeFollowsTheSafetyRules(): void {
		$this->loginsFromTheNetwork();
		$this->assertSame(BanResult::SKIPPED_SHARED, $this->bans->banNetwork(SourceKey::fromIp('198.51.100.7'), 'credential_stuffing')->outcome);
		$this->appConfig->setValueString('bruteForce', 'whitelist_1', '203.0.113.200/32');
		try {
			$this->assertSame(BanResult::SKIPPED_NEVER, $this->freshService()->banNetwork(SourceKey::fromIp('203.0.113.7'), 'credential_stuffing')->outcome);
		} finally {
			$this->appConfig->deleteKey('bruteForce', 'whitelist_1');
		}
		Server::get(LoginHistoryMapper::class)->insert('admin', time(), SourceKey::fromIp('192.0.2.200'), null, 'password', false, 'none', null, null);
		$this->assertSame(BanResult::SKIPPED_TRUSTED, $this->bans->banNetwork(SourceKey::fromIp('192.0.2.7'), 'credential_stuffing')->outcome);
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

	public function testSafetyValveCountsOnlyTheAddressForAnAddress(): void {
		$this->loginsFromTheNetwork();
		$result = $this->bans->ban(SourceKey::fromIp('198.51.100.99'), 'trap_url');
		$this->assertSame(BanResult::BANNED, $result->outcome, 'Other people in the /24 do not protect this address');
	}

	public function testSafetyValveKeepsANetworkWithManyPeopleUnblocked(): void {
		$this->loginsFromTheNetwork();
		foreach ([97, 98, 99] as $last) {
			$result = $this->bans->ban(SourceKey::fromIp('198.51.100.' . $last), 'trap_url');
			$this->assertSame(BanResult::BANNED, $result->outcome);
		}
		$this->assertNull($result->netBan, 'The /24 is not blocked');
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
		$versionBefore = Server::get(StateMapper::class)->get(AddressCache::VERSION_STATE);
		$this->bans->lift($result->ban, 'admin', 'false alarm');
		$this->assertNotSame($versionBefore, Server::get(StateMapper::class)->get(AddressCache::VERSION_STATE));
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

	public function testParallelRowsOfOneAddressCountOnceForTheNetwork(): void {
		foreach (['198.51.100.1', '198.51.100.1', '198.51.100.2'] as $ip) {
			$this->insertActiveBan($ip, $ip . '/32', Ban::SCOPE_IP);
		}
		$this->assertNull($this->bans->ban(SourceKey::fromIp('198.51.100.2'), 'trap_url')->netBan);
		$this->assertNotNull($this->bans->ban(SourceKey::fromIp('198.51.100.3'), 'trap_url')->netBan, 'The third address does it');
	}

	public function testOnlyTheAddressesOfTheSlash24Count(): void {
		// Keys that share a start with the /24's addresses, or sort right next to them.
		foreach (['198.51.10.1', '198.51.10.2', '198.51.1.3', '198.51.101.4', '198.51.100.0/24'] as $key) {
			$this->insertActiveBan($key, str_contains($key, '/') ? $key : $key . '/32', str_contains($key, '/') ? Ban::SCOPE_NET : Ban::SCOPE_IP, lifted: str_contains($key, '/'));
		}
		$this->assertNull($this->bans->ban(SourceKey::fromIp('198.51.100.1'), 'trap_url')->netBan);
		$this->assertNull($this->bans->ban(SourceKey::fromIp('198.51.100.255'), 'trap_url')->netBan);
		$this->assertNotNull($this->bans->ban(SourceKey::fromIp('198.51.100.20'), 'trap_url')->netBan, 'The third address of the /24 itself');
	}

	public function testTheNetworkKeyItselfIsNoAddressOfTheNetwork(): void {
		$this->insertActiveBan('198.51.100.0/24', '198.51.100.0/24', Ban::SCOPE_NET, lifted: true);
		$this->insertActiveBan('198.51.100.1', '198.51.100.1/32', Ban::SCOPE_IP);
		$this->assertNull($this->bans->ban(SourceKey::fromIp('198.51.100.2'), 'trap_url')->netBan);
	}

	public function testNoNetworkBlockOverAnAllowlistedAddress(): void {
		$this->appConfig->setValueString('bruteForce', 'whitelist_1', '198.51.100.200/32');
		try {
			foreach ([1, 2, 3] as $last) {
				$result = $this->freshService()->ban(SourceKey::fromIp('198.51.100.' . $last), 'trap_url');
				$this->assertSame(BanResult::BANNED, $result->outcome);
			}
			$this->assertNull($result->netBan);
		} finally {
			$this->appConfig->deleteKey('bruteForce', 'whitelist_1');
		}
	}

	public function testNoNetworkBlockOverTheServer(): void {
		$_SERVER['SERVER_ADDR'] = '198.51.100.250';
		try {
			foreach ([1, 2, 3] as $last) {
				$result = $this->freshService()->ban(SourceKey::fromIp('198.51.100.' . $last), 'trap_url');
			}
			$this->assertNull($result->netBan);
		} finally {
			unset($_SERVER['SERVER_ADDR']);
		}
	}

	public function testAnAdministratorsAddressIsNotBlockedAutomatically(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		Server::get(LoginHistoryMapper::class)->insert('admin', time() - 3 * 86400, $source, null, 'password', false, 'none', null, null);
		$this->assertSame(BanResult::SKIPPED_TRUSTED, $this->bans->ban($source, 'credential_stuffing')->outcome);
		$this->assertSame('198.51.100.7/32', $this->bans->banManually('198.51.100.7', 1, 'admin', null)->getCidr(), 'By hand it still works');
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function neverTrustedChecks(): array {
		return ['a trap URL' => ['trap_url'], 'an injection probe' => ['injection_probe']];
	}

	#[DataProvider('neverTrustedChecks')]
	public function testNoLoginExemptsFromTrapsAndProbes(string $checkId): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$history = Server::get(LoginHistoryMapper::class);
		$history->insert('admin', time() - 3600, $source, null, 'password', false, 'none', null, null);
		$history->insert('alice', time() - 3600, $source, null, 'password', true, 'second_factor', 'confirmed', null);
		$this->assertSame(BanResult::BANNED, $this->bans->ban($source, $checkId, uid: 'alice')->outcome);
	}

	/**
	 * @return array<string, array{bool, string, ?string}>
	 */
	public static function confirmedLogins(): array {
		return [
			'second factor' => [false, 'second_factor', 'confirmed'],
			'email code' => [false, 'email_code', 'confirmed'],
			'remembered device' => [true, 'none', null],
		];
	}

	#[DataProvider('confirmedLogins')]
	public function testAConfirmedLoginOnlyExemptsFromAttacksOnTheSameAccount(bool $knownDevice, string $confirmedBy, ?string $stepUp): void {
		$source = SourceKey::fromIp('198.51.100.7');
		Server::get(LoginHistoryMapper::class)->insert('alice', time() - 3 * 86400, $source, null, 'password', $knownDevice, $confirmedBy, $stepUp, null);
		$this->assertSame(BanResult::SKIPPED_TRUSTED, $this->bans->ban($source, 'account_under_attack', uid: 'alice')->outcome, 'Alice\'s own device with an old password');
		$this->assertSame(BanResult::BANNED, $this->bans->ban($source, 'account_under_attack', uid: 'bob')->outcome, 'An attack on someone else');
	}

	#[DataProvider('confirmedLogins')]
	public function testAConfirmedLoginDoesNotExemptFromChecksAboutManyAccounts(bool $knownDevice, string $confirmedBy, ?string $stepUp): void {
		$source = SourceKey::fromIp('198.51.100.7');
		// Anyone can register an account and confirm a login with it.
		Server::get(LoginHistoryMapper::class)->insert('self-registered', time() - 3600, $source, null, 'password', $knownDevice, $confirmedBy, $stepUp, null);
		foreach (['credential_stuffing', 'password_spraying', 'share_bruteforce', 'decoy_credential'] as $checkId) {
			$this->assertSame(BanResult::BANNED, $this->freshService()->ban($source, $checkId, uid: 'self-registered')->outcome, $checkId);
			$this->db->getQueryBuilder()->delete(BanMapper::TABLE)->executeStatement();
		}
	}

	/**
	 * @return array<string, array{string, string, ?string, int}>
	 */
	public static function untrustedLogins(): array {
		return [
			'a plain password login' => ['alice', 'none', null, 3600],
			'a refused confirmation' => ['alice', 'second_factor', 'refused', 3600],
			'a refused administrator' => ['admin', 'none', 'refused', 3600],
			'a pending confirmation' => ['alice', 'second_factor', 'pending', 3600],
			'a confirmation 8 days ago' => ['alice', 'second_factor', 'confirmed', 8 * 86400],
		];
	}

	#[DataProvider('untrustedLogins')]
	public function testOtherLoginsDoNotProtectAnAddress(string $uid, string $confirmedBy, ?string $stepUp, int $age): void {
		$source = SourceKey::fromIp('198.51.100.7');
		Server::get(LoginHistoryMapper::class)->insert($uid, time() - $age, $source, null, 'password', false, $confirmedBy, $stepUp, null);
		$this->assertSame(BanResult::BANNED, $this->bans->ban($source, 'account_under_attack', uid: $uid)->outcome);
	}

	public function testManyClientLoginsDoNotHideAnAdministrator(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$history = Server::get(LoginHistoryMapper::class);
		$history->insert('admin', time() - 2 * 86400, $source, null, 'password', false, 'none', null, null);
		for ($i = 0; $i < 120; $i++) {
			$history->insert('alice', time() - $i * 60, $source, null, 'app_password', false, 'none', null, null);
		}
		$this->assertSame(BanResult::SKIPPED_TRUSTED, $this->bans->ban($source, 'credential_stuffing')->outcome);
	}

	public function testAConfirmedLoginInTheSlash64ProtectsIpv6(): void {
		Server::get(LoginHistoryMapper::class)->insert('alice', time(), SourceKey::fromIp('2001:db8:1:2::5'), null, 'password', false, 'email_code', 'confirmed', null);
		$this->assertSame(BanResult::SKIPPED_TRUSTED, $this->bans->ban(SourceKey::fromIp('2001:db8:1:2::99'), 'account_under_attack', uid: 'alice')->outcome);
	}

	public function testAnAdministratorInTheNetworkKeepsItUnblocked(): void {
		Server::get(LoginHistoryMapper::class)->insert('admin', time(), SourceKey::fromIp('198.51.100.200'), null, 'password', false, 'none', null, null);
		foreach ([1, 2, 3] as $last) {
			$result = $this->bans->ban(SourceKey::fromIp('198.51.100.' . $last), 'credential_stuffing');
			$this->assertSame(BanResult::BANNED, $result->outcome);
		}
		$this->assertNull($result->netBan);
	}

	public function testAConfirmedLoginInTheNetworkDoesNotKeepItUnblockedForOthers(): void {
		Server::get(LoginHistoryMapper::class)->insert('alice', time(), SourceKey::fromIp('198.51.100.200'), null, 'password', false, 'second_factor', 'confirmed', null);
		foreach ([1, 2, 3] as $last) {
			$result = $this->bans->ban(SourceKey::fromIp('198.51.100.' . $last), 'credential_stuffing');
		}
		$this->assertSame('198.51.100.0/24', $result->netBan?->getCidr());
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function anyCheck(): array {
		return ['a trap URL' => ['trap_url'], 'credential stuffing' => ['credential_stuffing']];
	}

	#[DataProvider('anyCheck')]
	public function testAPrivateAddressAnAdministratorUsesIsNotBlockedWithoutTrustedProxies(string $checkId): void {
		// A small server behind a reverse proxy nobody configured: every request comes from the proxy.
		$proxy = SourceKey::fromIp('192.168.1.2');
		$history = Server::get(LoginHistoryMapper::class);
		$history->insert('admin', time() - 6 * 86400, $proxy, null, 'password', false, 'none', null, null);
		for ($i = 0; $i < 60; $i++) {
			$history->insert('alice', time() - $i * 60, $proxy, null, 'app_password', false, 'none', null, null);
		}
		$result = $this->bans->ban($proxy, $checkId);
		$this->assertSame(BanResult::SKIPPED_PROXY, $result->outcome);
		$this->assertSame(2, $result->sharedUsers);

		$config = Server::get(IConfig::class);
		$config->setSystemValue('trusted_proxies', ['10.0.0.1']);
		try {
			$expected = $checkId === 'trap_url' ? BanResult::BANNED : BanResult::SKIPPED_TRUSTED;
			$this->assertSame($expected, $this->freshService()->ban($proxy, $checkId)->outcome, 'With trusted proxies, the address is a person');
		} finally {
			$config->deleteSystemValue('trusted_proxies');
		}
	}

	public function testAnUnconfiguredReverseProxyIsNotBlocked(): void {
		$proxy = SourceKey::fromIp('10.0.0.2');
		$logins = Server::get(LoginMapper::class);
		foreach (['alice', 'bob', 'carol'] as $uid) {
			$logins->record($proxy->ipKey, $proxy->netKey, $uid, intdiv(time(), 3600));
		}
		$result = $this->bans->ban($proxy, 'trap_url');
		$this->assertSame(BanResult::SKIPPED_PROXY, $result->outcome);
		$this->assertSame(3, $result->sharedUsers);
		$this->assertSame(BanResult::BANNED, $this->bans->ban(SourceKey::fromIp('10.0.0.3'), 'trap_url')->outcome, 'Another private address is blocked');

		$config = Server::get(IConfig::class);
		$config->setSystemValue('trusted_proxies', ['10.0.0.1']);
		try {
			$this->assertSame(BanResult::BANNED, $this->bans->ban($proxy, 'trap_url')->outcome, 'With trusted proxies, Nextcloud sees the visitors');
		} finally {
			$config->deleteSystemValue('trusted_proxies');
		}
	}

	public function testThreeSlash64sOfASlash56BlockTheSlash56(): void {
		foreach (['2001:db8:1:2a01::1', '2001:db8:1:2a02::1'] as $ip) {
			$this->assertNull($this->bans->ban(SourceKey::fromIp($ip), 'trap_url')->netBan);
		}
		$third = $this->bans->ban(SourceKey::fromIp('2001:db8:1:2aff::1'), 'trap_url');
		$this->assertSame('2001:db8:1:2a00::/56', $third->netBan?->getCidr());
		$this->assertNull($this->bans->ban(SourceKey::fromIp('2001:db8:1:2a10::1'), 'trap_url')->netBan, 'Already covered');
		$resolver = Server::get(AddressResolver::class);
		$this->assertTrue($resolver->resolve(SourceKey::fromIp('2001:db8:1:2a77::1'))->isDenied(time()), 'Another /64 of the /56 is blocked');
		$this->assertFalse($resolver->resolve(SourceKey::fromIp('2001:db8:1:2b00::1'))->isDenied(time()), 'The next /56 is not');
	}

	public function testSlash64sAllOverASlash48BlockTheSlash48(): void {
		$result = null;
		for ($i = 1; $i <= 9; $i++) {
			$result = $this->bans->ban(SourceKey::fromIp(sprintf('2001:db8:7:%x00::1', $i * 16)), 'trap_url');
			if ($i < 9) {
				$this->assertNull($result->netBan, (string)$i);
			}
		}
		$this->assertSame('2001:db8:7::/48', $result?->netBan?->getCidr());
		$this->assertTrue(Server::get(AddressResolver::class)->resolve(SourceKey::fromIp('2001:db8:7:ffff::1'))->isDenied(time()));
	}

	public function testIpv6NetworksFollowTheSafetyRules(): void {
		Server::get(LoginHistoryMapper::class)->insert('admin', time(), SourceKey::fromIp('2001:db8:1:2a50::5'), null, 'password', true, 'known_device', null, null);
		foreach (['2001:db8:1:2a01::1', '2001:db8:1:2a02::1', '2001:db8:1:2a03::1'] as $ip) {
			$result = $this->bans->ban(SourceKey::fromIp($ip), 'credential_stuffing');
			$this->assertSame(BanResult::BANNED, $result->outcome);
		}
		$this->assertNull($result->netBan, 'An administrator logged in from the /56');
	}

	public function testTheServerSeenInWebRequestsIsNeverBlockedFromCronOrOcc(): void {
		$_SERVER['SERVER_ADDR'] = '192.0.2.10';
		try {
			Server::get(ServerAddresses::class)->observe();
		} finally {
			unset($_SERVER['SERVER_ADDR']);
		}
		$bans = $this->freshService();
		$this->assertSame(BanResult::SKIPPED_NEVER, $bans->ban(SourceKey::fromIp('192.0.2.10'), 'credential_stuffing')->outcome);
		foreach (['192.0.2.10', '192.0.2.0/24'] as $target) {
			try {
				$bans->banManually($target, 1, 'admin', null);
				$this->fail($target . ' was blocked');
			} catch (BanRefusedException) {
			}
		}
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function neverBlockedTargets(): array {
		return [
			'loopback' => ['127.0.0.1'],
			'loopback network' => ['127.0.0.0/24'],
			'IPv6 loopback' => ['::1'],
			'the allowlist' => ['203.0.113.9'],
			'a network around the allowlist' => ['203.0.113.0/24'],
			'the server' => ['192.0.2.10'],
			'a network around the server' => ['192.0.2.0/24'],
		];
	}

	#[DataProvider('neverBlockedTargets')]
	public function testBlocksByHandRefuseWhatIsNeverBlocked(string $target): void {
		$this->appConfig->setValueString('bruteForce', 'whitelist_1', '203.0.113.9/32');
		$_SERVER['SERVER_ADDR'] = '192.0.2.10';
		try {
			$this->expectException(BanRefusedException::class);
			$this->freshService()->banManually($target, 1, 'admin', null);
		} finally {
			unset($_SERVER['SERVER_ADDR']);
			$this->appConfig->deleteKey('bruteForce', 'whitelist_1');
		}
	}

	public function testTheCheckAndTheInsertRunUnderALockPerAddress(): void {
		$locks = $this->createMock(ILockingProvider::class);
		$calls = [];
		$locks->method('acquireLock')->willReturnCallback(function (string $path) use (&$calls): void {
			$calls[] = 'acquire ' . $path;
			if (count($calls) === 1) {
				throw new LockedException($path);
			}
		});
		$locks->method('releaseLock')->willReturnCallback(function (string $path) use (&$calls): void {
			$calls[] = 'release ' . $path;
		});
		$result = $this->freshService($locks)->ban(SourceKey::fromIp('198.51.100.7'), 'trap_url');
		$this->assertSame(BanResult::BANNED, $result->outcome);
		$lock = 'intrusion_detection/ban/' . md5('198.51.100.7');
		$this->assertSame(['acquire ' . $lock, 'acquire ' . $lock, 'release ' . $lock], $calls, 'Waits for the lock, then holds it while it checks and inserts; a network far from its threshold takes none');
		$this->assertLessThanOrEqual(64, strlen($lock), 'Fits the database lock table');
	}

	public function testABlockedOrExemptAddressTakesNoLock(): void {
		$this->bans->ban(SourceKey::fromIp('198.51.100.7'), 'trap_url');
		$this->bans->banNetwork(SourceKey::fromIp('203.0.113.1'), 'credential_stuffing');
		Server::get(LoginHistoryMapper::class)->insert('admin', time(), SourceKey::fromIp('192.0.2.7'), null, 'password', false, 'none', null, null);
		$locks = $this->createMock(ILockingProvider::class);
		$locks->expects($this->never())->method('acquireLock');
		$bans = $this->freshService($locks);
		$this->assertSame(BanResult::ALREADY, $bans->ban(SourceKey::fromIp('198.51.100.7'), 'password_spraying')->outcome);
		$this->assertSame(BanResult::ALREADY, $bans->ban(SourceKey::fromIp('203.0.113.99'), 'password_spraying')->outcome, 'Inside a blocked /24');
		$this->assertSame(BanResult::SKIPPED_TRUSTED, $bans->ban(SourceKey::fromIp('192.0.2.7'), 'password_spraying')->outcome);
		$this->assertSame(BanResult::ALREADY, $bans->banNetwork(SourceKey::fromIp('203.0.113.5'), 'credential_stuffing')->outcome);
	}

	public function testManyAddressesAreBlockedWithOneEscalationPerNetworkAndOneVersion(): void {
		$state = Server::get(StateMapper::class);
		$targets = [];
		for ($i = 1; $i <= 6; $i++) {
			$targets[] = SourceKey::fromIp('198.51.100.' . $i);
			$targets[] = SourceKey::fromIp('203.0.113.' . $i);
		}
		$targets[] = SourceKey::fromIp('192.0.2.1');
		$writes = 0;
		$results = $this->freshService(state: $this->countingState($writes))->banMany($targets, 'password_spraying', 7);
		$this->assertCount(13, $results);
		$this->assertSame(1, $writes, 'The cached verdicts change once');
		$this->assertCount(1, $this->mapper->findActiveForKeys(['198.51.100.0/24'], time()));
		$this->assertCount(1, $this->mapper->findActiveForKeys(['203.0.113.0/24'], time()));
		$this->assertSame([], $this->mapper->findActiveForKeys(['192.0.2.0/24'], time()));
		$netBans = array_filter($results, static fn (BanResult $r): bool => $r->netBan !== null);
		$this->assertCount(2, $netBans, 'Each network is blocked once, in the result of the address that did it');

		$again = $this->freshService()->banMany($targets, 'password_spraying', 7);
		$this->assertSame([BanResult::ALREADY], array_values(array_unique(array_map(static fn (BanResult $r): string => $r->outcome, $again))));
		$this->assertNotNull($state->get(AddressCache::VERSION_STATE));
	}

	public function testAStuckLockDoesNotStopTheBlock(): void {
		$locks = $this->createMock(ILockingProvider::class);
		$locks->method('acquireLock')->willThrowException(new LockedException('x'));
		$locks->expects($this->never())->method('releaseLock');
		$this->assertSame(BanResult::BANNED, $this->freshService($locks)->ban(SourceKey::fromIp('198.51.100.7'), 'trap_url')->outcome);
	}

	public function testLiftingABlockRemovesTheFlagOfItsAddress(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$flags = Server::get(FlaggedSources::class);
		$flags->flagSource($source, FlaggedSources::REASON_ATTACK);
		$flags->flagNetwork($source, FlaggedSources::REASON_DISTRIBUTED);
		$this->bans->lift($this->bans->ban($source, 'trap_url')->ban, 'admin', 'false alarm');
		$this->assertSame(FlaggedSources::REASON_DISTRIBUTED, $flags->sourceFlag($source), 'The address flag is gone, the /24 flag of another detection stays');
	}

	public function testEndedBlocksFlagTheirAddressAtTheNextCleanup(): void {
		$ended = SourceKey::fromIp('198.51.100.7');
		$lifted = SourceKey::fromIp('198.51.100.8');
		$network = SourceKey::fromIp('203.0.113.9');
		$running = SourceKey::fromIp('192.0.2.5');
		$ipv6 = SourceKey::fromIp('2001:db8:1:2::9');
		$this->insertBan($ended->ipKey, $ended->ip . '/32', time() - 600);
		$this->insertBan($lifted->ipKey, $lifted->ip . '/32', time() - 600, lifted: true);
		$this->insertBan($network->netKey, $network->netKey, time() - 600);
		$this->insertBan($running->ipKey, $running->ip . '/32', time() + 600);
		$this->insertBan($ipv6->ipKey, $ipv6->ipKey, time() - 60);
		$this->insertBan('2001:db8:1::/48', '2001:db8:1::/48', time() - 60);
		$this->insertBan('198.51.100.99', '198.51.100.99/32', time() - 2 * 86400);

		self::invokePrivate(Server::get(Cleanup::class), 'run', [null]);
		$flags = Server::get(FlaggedSources::class);
		$this->assertSame(FlaggedSources::REASON_BAN_EXPIRED, $flags->sourceFlag($ended));
		$this->assertNull($flags->sourceFlag($lifted), 'A lifted block was a mistake');
		$this->assertSame(FlaggedSources::REASON_BAN_EXPIRED, $flags->sourceFlag(SourceKey::fromIp('203.0.113.200')), 'The ended /24');
		$this->assertNull($flags->sourceFlag($running));
		$this->assertSame(FlaggedSources::REASON_BAN_EXPIRED, $flags->sourceFlag(SourceKey::fromIp('2001:db8:1:2::77')));
		$this->assertNull($flags->sourceFlag(SourceKey::fromIp('2001:db8:1:5::1')), 'Wider IPv6 networks are not flagged');
		$this->assertNull($flags->sourceFlag(SourceKey::fromIp('198.51.100.99')), 'Its flag would have ended already');
		$this->assertSame(time(), $this->appConfig->getValueInt(Application::APP_ID, GlobalSettings::BANS_FLAGGED_UNTIL), 'Progress is kept');

		$flags->unflagSource($ended);
		self::invokePrivate(Server::get(Cleanup::class), 'run', [null]);
		$this->assertNull($flags->sourceFlag($ended), 'A block is flagged once');
	}

	private function loginsFromTheNetwork(): void {
		$logins = Server::get(LoginMapper::class);
		$hour = intdiv(time(), 3600);
		foreach (['alice', 'bob', 'carol', 'dave', 'erin'] as $i => $uid) {
			$other = SourceKey::fromIp('198.51.100.' . (10 + $i));
			$logins->record($other->ipKey, $other->netKey, $uid, $hour);
		}
	}

	/**
	 * The service with nothing cached from earlier tests (the allowlist and
	 * server ranges are read once per instance).
	 */
	private function freshService(?ILockingProvider $locks = null, ?StateMapper $state = null): BanService {
		$ranges = new ProtectedRanges($this->appConfig, Server::get(ServerAddresses::class));
		return new BanService(
			$this->mapper,
			new BanExemptions(
				Server::get(LoginMapper::class),
				Server::get(LoginHistoryMapper::class),
				Server::get(Settings::class),
				Server::get(ProxySuspect::class),
				$ranges,
				Server::get(IGroupManager::class),
				Server::get(ICacheFactory::class),
			),
			Server::get(Settings::class),
			$state === null ? Server::get(AddressCache::class) : new AddressCache(Server::get(ICacheFactory::class), $state),
			Server::get(AddressResolver::class),
			new RemoteAddressResolver($this->createMock(IRequest::class), Server::get(IThrottler::class), Server::get(ServerAddresses::class)),
			$ranges,
			Server::get(FlaggedSources::class),
			new KeyLock($locks ?? Server::get(ILockingProvider::class)),
			Server::get(ITimeFactory::class),
			Server::get(ISecureRandom::class),
			Server::get(TypedEvents::class),
		);
	}

	/**
	 * The state table, counting the writes of the verdict version.
	 */
	private function countingState(int &$writes): StateMapper {
		$real = Server::get(StateMapper::class);
		$state = $this->createMock(StateMapper::class);
		$state->method('get')->willReturnCallback(static fn (string $name): ?string => $real->get($name));
		$state->method('set')->willReturnCallback(static function (string $name, string $value) use ($real, &$writes): void {
			$writes++;
			$real->set($name, $value);
		});
		return $state;
	}

	private function insertBan(string $banKey, string $cidr, int $expiresAt, bool $lifted = false): void {
		$ban = new Ban();
		$ban->setReference(substr(str_shuffle('ABCDEFGHJKLMNPQRSTUVWXYZ23456789'), 0, 8));
		$ban->setCidr($cidr);
		$ban->setScope(str_ends_with($cidr, '/32') ? Ban::SCOPE_IP : Ban::SCOPE_NET);
		$ban->setBanKey($banKey);
		$ban->setLevel(1);
		$ban->setCheckId('trap_url');
		$ban->setCreatedAt($expiresAt - 3600);
		$ban->setExpiresAt($expiresAt);
		$ban->setLiftedAt($lifted ? $expiresAt - 60 : null);
		$this->mapper->insert($ban);
	}

	private function insertActiveBan(string $banKey, string $cidr, string $scope, bool $lifted = false): void {
		$ban = new Ban();
		$ban->setReference(substr(str_shuffle('ABCDEFGHJKLMNPQRSTUVWXYZ23456789'), 0, 8));
		$ban->setCidr($cidr);
		$ban->setScope($scope);
		$ban->setBanKey($banKey);
		$ban->setLevel(1);
		$ban->setCheckId('trap_url');
		$ban->setCreatedAt(time());
		$ban->setExpiresAt(time() + 14400);
		$ban->setLiftedAt($lifted ? time() : null);
		$this->mapper->insert($ban);
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
